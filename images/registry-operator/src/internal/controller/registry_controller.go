package controller

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
	"registry-operator/internal/registry"
)

const defaultScanInterval = 300

type RegistryReconciler struct {
	client.Client
}

func newRegistryReconciler(mgr ctrl.Manager) *RegistryReconciler {
	return &RegistryReconciler{
		Client: mgr.GetClient(),
	}
}

func (r *RegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	registryResource, err := r.fetchRegistry(ctx, req.NamespacedName)
	if err != nil {
		return ctrl.Result{}, err
	}
	if registryResource == nil {
		logger.V(1).Info("registry not found or being deleted")
		return ctrl.Result{}, nil
	}

	logger.Info("reconciling", "registry", req.NamespacedName)

	images, err := r.scanRegistry(ctx, registryResource)
	if err != nil {
		return r.handleScanFailure(ctx, registryResource, err)
	}

	if err := r.updateStatusSuccess(ctx, registryResource, images); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: r.getRequeueInterval(registryResource)}, nil
}

func (r *RegistryReconciler) fetchRegistry(ctx context.Context, key types.NamespacedName) (*v1alpha1.Registry, error) {
	var registryResource v1alpha1.Registry
	if err := r.Get(ctx, key, &registryResource); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if !registryResource.DeletionTimestamp.IsZero() {
		return nil, nil
	}

	return &registryResource, nil
}

func (r *RegistryReconciler) scanRegistry(ctx context.Context, registryResource *v1alpha1.Registry) ([]v1alpha1.ImageInfo, error) {
	logger := log.FromContext(ctx)

	username, password, err := r.getCredentials(ctx, registryResource)
	if err != nil {
		return nil, err
	}

	registryClient := registry.NewClient(
		registryResource.Spec.URL,
		username,
		password,
		registryResource.Spec.InsecureSkipVerify,
	)

	tags, err := registryClient.ListTags(ctx, registryResource.Spec.Repository)
	if err != nil {
		return nil, err
	}

	return r.fetchImageDetails(ctx, logger, registryClient, registryResource.Spec.Repository, tags)
}

func (r *RegistryReconciler) fetchImageDetails(
	ctx context.Context,
	logger logr.Logger,
	registryClient *registry.Client,
	repository string,
	tags []string,
) ([]v1alpha1.ImageInfo, error) {
	images := make([]v1alpha1.ImageInfo, 0, len(tags))

	for _, tag := range tags {
		imageInfo := v1alpha1.ImageInfo{Tag: tag}

		details, err := registryClient.GetImageDetails(ctx, repository, tag)
		if err != nil {
			logger.V(1).Info("failed to get image details", "tag", tag, "error", err)
		} else {
			imageInfo.Digest = details.Digest
			imageInfo.Size = details.Size
		}

		images = append(images, imageInfo)
	}

	return images, nil
}

func (r *RegistryReconciler) getCredentials(ctx context.Context, registryResource *v1alpha1.Registry) (string, string, error) {
	secretRef := registryResource.Spec.CredentialsSecret
	if secretRef == nil {
		return "", "", nil
	}

	var secret corev1.Secret
	secretKey := types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: registryResource.Namespace,
	}
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		return "", "", err
	}

	usernameKey := secretRef.UsernameKey
	if usernameKey == "" {
		usernameKey = "username"
	}

	passwordKey := secretRef.PasswordKey
	if passwordKey == "" {
		passwordKey = "password"
	}

	return string(secret.Data[usernameKey]), string(secret.Data[passwordKey]), nil
}

func (r *RegistryReconciler) handleScanFailure(ctx context.Context, registryResource *v1alpha1.Registry, scanErr error) (ctrl.Result, error) {
	if err := r.updateStatusFailed(ctx, registryResource, scanErr.Error()); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, scanErr
}

func (r *RegistryReconciler) updateStatusSuccess(ctx context.Context, registryResource *v1alpha1.Registry, images []v1alpha1.ImageInfo) error {
	return r.updateStatus(ctx, registryResource, "Success", "", images)
}

func (r *RegistryReconciler) updateStatusFailed(ctx context.Context, registryResource *v1alpha1.Registry, message string) error {
	return r.updateStatus(ctx, registryResource, "Failed", message, nil)
}

func (r *RegistryReconciler) updateStatus(ctx context.Context, registryResource *v1alpha1.Registry, scanStatus, message string, images []v1alpha1.ImageInfo) error {
	now := metav1.Now()
	registryResource.Status.LastScanTime = &now
	registryResource.Status.LastScanStatus = scanStatus
	registryResource.Status.Message = message
	registryResource.Status.Images = images

	err := r.Status().Update(ctx, registryResource)
	if apierrors.IsConflict(err) {
		return r.retryStatusUpdate(ctx, registryResource, scanStatus, message, images, now)
	}
	return err
}

func (r *RegistryReconciler) retryStatusUpdate(
	ctx context.Context,
	registryResource *v1alpha1.Registry,
	scanStatus, message string,
	images []v1alpha1.ImageInfo,
	timestamp metav1.Time,
) error {
	var latestRegistry v1alpha1.Registry
	registryKey := types.NamespacedName{
		Name:      registryResource.Name,
		Namespace: registryResource.Namespace,
	}

	if err := r.Get(ctx, registryKey, &latestRegistry); err != nil {
		return err
	}

	latestRegistry.Status.LastScanTime = &timestamp
	latestRegistry.Status.LastScanStatus = scanStatus
	latestRegistry.Status.Message = message
	latestRegistry.Status.Images = images

	return r.Status().Update(ctx, &latestRegistry)
}

func (r *RegistryReconciler) getRequeueInterval(registryResource *v1alpha1.Registry) time.Duration {
	interval := registryResource.Spec.ScanInterval
	if interval <= 0 {
		interval = defaultScanInterval
	}
	return time.Duration(interval) * time.Second
}

func SetupRegistryController(mgr ctrl.Manager) error {
	reconciler := newRegistryReconciler(mgr)
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Registry{}).
		Complete(reconciler)
}
