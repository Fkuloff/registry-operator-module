package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// handleScanFailure updates status with failure information.
func (r *RegistryReconciler) handleScanFailure(ctx context.Context, reg *v1alpha1.Registry, scanErr error) (ctrl.Result, error) {
	if err := r.updateStatusFailed(ctx, reg, scanErr.Error()); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, scanErr
}

// updateStatusSuccess updates Registry status with successful scan results.
func (r *RegistryReconciler) updateStatusSuccess(
	ctx context.Context,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
	driftStatus *v1alpha1.DriftStatus,
) error {
	return r.updateStatus(ctx, reg, "Success", "", images, driftStatus)
}

// updateStatusFailed updates Registry status with failure information.
func (r *RegistryReconciler) updateStatusFailed(ctx context.Context, reg *v1alpha1.Registry, message string) error {
	return r.updateStatus(ctx, reg, "Failed", message, nil, nil)
}

// updateStatus updates the Registry status subresource.
func (r *RegistryReconciler) updateStatus(
	ctx context.Context,
	reg *v1alpha1.Registry,
	scanStatus, message string,
	images []v1alpha1.ImageInfo,
	driftStatus *v1alpha1.DriftStatus,
) error {
	now := metav1.Now()
	reg.Status.LastScanTime = &now
	reg.Status.LastScanStatus = scanStatus
	reg.Status.Message = message
	reg.Status.Images = images
	reg.Status.Drift = driftStatus

	err := r.client.Status().Update(ctx, reg)
	if apierrors.IsConflict(err) {
		return r.retryStatusUpdate(ctx, reg, scanStatus, message, images, driftStatus, now)
	}
	return err
}

// retryStatusUpdate retries status update after a conflict.
func (r *RegistryReconciler) retryStatusUpdate(
	ctx context.Context,
	reg *v1alpha1.Registry,
	scanStatus, message string,
	images []v1alpha1.ImageInfo,
	driftStatus *v1alpha1.DriftStatus,
	timestamp metav1.Time,
) error {
	regKey := types.NamespacedName{
		Name:      reg.Name,
		Namespace: reg.Namespace,
	}

	var latest v1alpha1.Registry
	if err := r.client.Get(ctx, regKey, &latest); err != nil {
		return fmt.Errorf("get latest registry: %w", err)
	}

	latest.Status.LastScanTime = &timestamp
	latest.Status.LastScanStatus = scanStatus
	latest.Status.Message = message
	latest.Status.Images = images
	latest.Status.Drift = driftStatus

	return r.client.Status().Update(ctx, &latest)
}
