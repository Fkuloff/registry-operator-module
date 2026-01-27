// Package main is the entry point for the registry-operator.
package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"registry-operator/internal/controller"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

var _scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(_scheme))
	utilruntime.Must(v1alpha1.AddToScheme(_scheme))
}

type config struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	developmentMode      bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{
		Development: cfg.developmentMode,
	})))

	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 _scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeaderElection,
		LeaderElectionID:       "registry-controller.kubecontroller.io",
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := controller.SetupRegistryController(mgr); err != nil {
		return fmt.Errorf("setup registry controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("setup health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("setup ready check: %w", err)
	}

	setupLog.Info("starting manager")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}

	return nil
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "address for metrics endpoint")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "address for health probe endpoint")
	flag.BoolVar(&cfg.enableLeaderElection, "leader-elect", false, "enable leader election for controller manager")
	flag.BoolVar(&cfg.developmentMode, "development", false, "enable development mode logging")
	flag.Parse()

	return cfg
}
