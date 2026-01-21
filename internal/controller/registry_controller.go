package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "kube-controller/api/v1alpha1"
	"kube-controller/internal/registry"
)

const defaultScanInterval = 300

type RegistryReconciler struct {
	client.Client
}

func (r *RegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var reg v1alpha1.Registry
	if err := r.Get(ctx, req.NamespacedName, &reg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("reconciling", "registry", req.NamespacedName)

	username, password, err := r.getCredentials(ctx, &reg)
	if err != nil {
		return r.failWithStatus(ctx, &reg, err)
	}

	c := registry.NewClient(reg.Spec.URL, username, password, reg.Spec.InsecureSkipVerify)

	tags, err := c.ListTags(reg.Spec.Repository)
	if err != nil {
		return r.failWithStatus(ctx, &reg, err)
	}

	images := make([]v1alpha1.ImageInfo, 0, len(tags))
	for _, tag := range tags {
		info := v1alpha1.ImageInfo{Tag: tag}
		if details, err := c.GetImageDetails(reg.Spec.Repository, tag); err == nil {
			info.Digest = details.Digest
			info.Size = details.Size
		}
		images = append(images, info)
	}

	if err := r.updateStatus(ctx, &reg, "Success", "", images); err != nil {
		return ctrl.Result{}, err
	}

	interval := reg.Spec.ScanInterval
	if interval <= 0 {
		interval = defaultScanInterval
	}
	return ctrl.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}

func (r *RegistryReconciler) getCredentials(ctx context.Context, reg *v1alpha1.Registry) (string, string, error) {
	ref := reg.Spec.CredentialsSecret
	if ref == nil {
		return "", "", nil
	}

	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: reg.Namespace}, &secret); err != nil {
		return "", "", err
	}

	usernameKey, passwordKey := ref.UsernameKey, ref.PasswordKey
	if usernameKey == "" {
		usernameKey = "username"
	}
	if passwordKey == "" {
		passwordKey = "password"
	}

	return string(secret.Data[usernameKey]), string(secret.Data[passwordKey]), nil
}

func (r *RegistryReconciler) failWithStatus(ctx context.Context, reg *v1alpha1.Registry, err error) (ctrl.Result, error) {
	if statusErr := r.updateStatus(ctx, reg, "Failed", err.Error(), nil); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{}, err
}

func (r *RegistryReconciler) updateStatus(ctx context.Context, reg *v1alpha1.Registry, status, message string, images []v1alpha1.ImageInfo) error {
	now := metav1.Now()
	reg.Status.LastScanTime = &now
	reg.Status.LastScanStatus = status
	reg.Status.Message = message
	reg.Status.Images = images

	if err := r.Status().Update(ctx, reg); err != nil {
		if apierrors.IsConflict(err) {
			return nil
		}
		return err
	}
	return nil
}

func (r *RegistryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Registry{}).
		Complete(r)
}
