// Package controller implements the Registry controller.
package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

const _registryFinalizer = "registry.kubecontroller.io/finalizer"

// RegistryReconciler reconciles Registry resources.
type RegistryReconciler struct {
	client client.Client
}

// newRegistryReconciler creates a new RegistryReconciler.
func newRegistryReconciler(mgr ctrl.Manager) *RegistryReconciler {
	return &RegistryReconciler{
		client: mgr.GetClient(),
	}
}

// Reconcile handles the reconciliation loop for Registry resources.
func (r *RegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var reg v1alpha1.Registry
	if err := r.client.Get(ctx, req.NamespacedName, &reg); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("registry not found, likely deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !reg.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &reg)
	}

	if !controllerutil.ContainsFinalizer(&reg, _registryFinalizer) {
		logger.Info("adding finalizer", "registry", req.NamespacedName)
		controllerutil.AddFinalizer(&reg, _registryFinalizer)
		if err := r.client.Update(ctx, &reg); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	logger.Info("reconciling", "registry", req.NamespacedName)

	images, err := r.scanRegistry(ctx, &reg)
	if err != nil {
		return r.handleScanFailure(ctx, &reg, err)
	}

	if r.shouldScanVulnerabilities(&reg) {
		images = r.scanVulnerabilities(ctx, logger, &reg, images)
	}

	if r.shouldScanSBOM(&reg) {
		images = r.scanSBOM(ctx, logger, &reg, images)
	}

	if r.shouldScanProvenance(&reg) {
		username, password, _ := r.getCredentials(ctx, &reg)
		images = r.scanProvenance(ctx, logger, &reg, images, username, password)
	}

	var driftStatus *v1alpha1.DriftStatus
	if r.shouldDetectDrift(&reg) {
		driftStatus = r.detectDrift(ctx, logger, &reg, images)
	}

	if err := r.updateStatusSuccess(ctx, &reg, images, driftStatus); err != nil {
		return ctrl.Result{}, err
	}

	if r.shouldSendWebhook(&reg) {
		webhookStatus := r.sendWebhookNotifications(ctx, logger, &reg, images)
		if webhookStatus != nil {
			reg.Status.Webhook = webhookStatus
			if err := r.client.Status().Update(ctx, &reg); err != nil {
				logger.V(1).Info("update webhook status: failed", "error", err)
			}
		}
	}

	return ctrl.Result{RequeueAfter: r.getRequeueInterval(&reg)}, nil
}

// handleDeletion processes Registry deletion with finalizer cleanup.
func (r *RegistryReconciler) handleDeletion(ctx context.Context, reg *v1alpha1.Registry) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(reg, _registryFinalizer) {
		return ctrl.Result{}, nil
	}

	logger.Info("running cleanup for registry",
		"name", reg.Name,
		"namespace", reg.Namespace,
	)

	if err := r.cleanup(ctx, reg); err != nil {
		logger.Error(err, "cleanup registry: failed")
		return ctrl.Result{}, err
	}

	logger.Info("removing finalizer", "registry", reg.Name)
	controllerutil.RemoveFinalizer(reg, _registryFinalizer)
	if err := r.client.Update(ctx, reg); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("cleanup completed successfully", "registry", reg.Name)
	return ctrl.Result{}, nil
}

// cleanup performs cleanup tasks when a Registry is deleted.
func (r *RegistryReconciler) cleanup(ctx context.Context, reg *v1alpha1.Registry) error {
	logger := log.FromContext(ctx)

	logger.Info("cleaning up registry resource",
		"name", reg.Name,
		"namespace", reg.Namespace,
		"url", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"totalImagesTracked", len(reg.Status.Images),
	)

	if err := r.deleteAssociatedConfigMap(ctx, reg); err != nil {
		logger.V(1).Info("no associated configmap to delete or error", "error", err)
	}

	return nil
}

// deleteAssociatedConfigMap deletes the ConfigMap associated with a Registry.
func (r *RegistryReconciler) deleteAssociatedConfigMap(ctx context.Context, reg *v1alpha1.Registry) error {
	configMapKey := types.NamespacedName{
		Name:      reg.Name + "-images",
		Namespace: reg.Namespace,
	}

	var configMap corev1.ConfigMap
	if err := r.client.Get(ctx, configMapKey, &configMap); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.client.Delete(ctx, &configMap)
}

// SetupRegistryController sets up the Registry controller with the Manager.
func SetupRegistryController(mgr ctrl.Manager) error {
	reconciler := newRegistryReconciler(mgr)
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Registry{}).
		Complete(reconciler)
}
