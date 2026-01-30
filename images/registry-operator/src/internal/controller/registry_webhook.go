package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
	"registry-operator/internal/webhook"
)

// shouldSendWebhook checks if webhook notifications are enabled and configured.
func (r *RegistryReconciler) shouldSendWebhook(reg *v1alpha1.Registry) bool {
	whConfig := reg.Spec.Webhook
	if whConfig == nil || !whConfig.Enabled {
		return false
	}
	return whConfig.URL != ""
}

// sendWebhookNotifications sends notifications for triggered events.
func (r *RegistryReconciler) sendWebhookNotifications(
	ctx context.Context,
	logger logr.Logger,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
) *v1alpha1.WebhookStatus {
	whConfig := reg.Spec.Webhook
	if whConfig == nil {
		return nil
	}

	authType, authToken, authUsername, authPassword, err := r.getWebhookAuth(ctx, reg)
	if err != nil {
		logger.Error(err, "get webhook auth: failed")
		return &v1alpha1.WebhookStatus{
			LastStatus: "Failed",
			Message:    fmt.Sprintf("get auth: %v", err),
		}
	}

	timeout := _defaultWebhookTimeout
	if whConfig.Timeout != "" {
		if d, parseErr := time.ParseDuration(whConfig.Timeout); parseErr == nil {
			timeout = d
		}
	}

	sender := webhook.NewSender(webhook.Config{
		URL:                whConfig.URL,
		AuthType:           authType,
		AuthToken:          authToken,
		AuthUsername:       authUsername,
		AuthPassword:       authPassword,
		Timeout:            timeout,
		InsecureSkipVerify: whConfig.InsecureSkipVerify,
	})

	payloads := r.buildWebhookPayloads(reg, images, whConfig.Events)
	if len(payloads) == 0 {
		return nil
	}

	logger.Info("sending webhook notifications", "count", len(payloads), "url", whConfig.URL)

	var lastStatus *v1alpha1.WebhookStatus
	for _, payload := range payloads {
		if err := sender.Send(ctx, payload); err != nil {
			logger.Error(err, "send webhook: failed", "event", payload.Event)
			lastStatus = &v1alpha1.WebhookStatus{
				LastSentTime: ptr(metav1.Now()),
				LastStatus:   "Failed",
				LastEvent:    payload.Event,
				Message:      err.Error(),
			}
			continue
		}

		logger.Info("webhook sent", "event", payload.Event)
		lastStatus = &v1alpha1.WebhookStatus{
			LastSentTime: ptr(metav1.Now()),
			LastStatus:   "Sent",
			LastEvent:    payload.Event,
		}
	}

	return lastStatus
}

// getWebhookAuth retrieves webhook authentication credentials from a Secret.
func (r *RegistryReconciler) getWebhookAuth(
	ctx context.Context,
	reg *v1alpha1.Registry,
) (authType, token, username, password string, err error) {
	whConfig := reg.Spec.Webhook
	if whConfig == nil || whConfig.AuthSecret == nil {
		return "", "", "", "", nil
	}

	authSecret := whConfig.AuthSecret
	secretKey := types.NamespacedName{
		Name:      authSecret.Name,
		Namespace: reg.Namespace,
	}

	var secret corev1.Secret
	if err := r.client.Get(ctx, secretKey, &secret); err != nil {
		return "", "", "", "", fmt.Errorf("get secret %s: %w", authSecret.Name, err)
	}

	// Check for Bearer token first
	if authSecret.TokenKey != "" {
		if tokenData, ok := secret.Data[authSecret.TokenKey]; ok && len(tokenData) > 0 {
			return "bearer", string(tokenData), "", "", nil
		}
	}

	// Fall back to Basic auth
	usernameKey := authSecret.UsernameKey
	if usernameKey == "" {
		usernameKey = "username"
	}
	passwordKey := authSecret.PasswordKey
	if passwordKey == "" {
		passwordKey = "password"
	}

	if usernameData, ok := secret.Data[usernameKey]; ok && len(usernameData) > 0 {
		return "basic", "", string(usernameData), string(secret.Data[passwordKey]), nil
	}

	return "", "", "", "", nil
}

// buildWebhookPayloads creates payloads based on subscribed events.
func (r *RegistryReconciler) buildWebhookPayloads(
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
	subscribedEvents []string,
) []*webhook.Payload {
	var payloads []*webhook.Payload
	now := time.Now().UTC().Format(time.RFC3339)

	registryInfo := webhook.RegistryInfo{
		Name:       reg.Name,
		Namespace:  reg.Namespace,
		URL:        reg.Spec.URL,
		Repository: reg.Spec.Repository,
	}

	subscribeAll := len(subscribedEvents) == 0

	// scan-completed event
	if subscribeAll || slices.Contains(subscribedEvents, "scan-completed") {
		payloads = append(payloads, buildScanCompletedPayload(now, registryInfo, images))
	}

	// vulnerability-critical event
	if subscribeAll || slices.Contains(subscribedEvents, "vulnerability-critical") {
		if payload := buildVulnerabilityCriticalPayload(now, registryInfo, images); payload != nil {
			payloads = append(payloads, payload)
		}
	}

	return payloads
}

// buildScanCompletedPayload creates a scan-completed event payload.
func buildScanCompletedPayload(
	timestamp string,
	registryInfo webhook.RegistryInfo,
	images []v1alpha1.ImageInfo,
) *webhook.Payload {
	var vulnSummary *webhook.VulnerabilitySummary
	var critical, high, medium, low, total int

	for _, img := range images {
		if img.Vulnerabilities == nil {
			continue
		}
		critical += img.Vulnerabilities.Critical
		high += img.Vulnerabilities.High
		medium += img.Vulnerabilities.Medium
		low += img.Vulnerabilities.Low
		total += img.Vulnerabilities.Total
	}

	if total > 0 {
		vulnSummary = &webhook.VulnerabilitySummary{
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
			Total:    total,
		}
	}

	return &webhook.Payload{
		Event:     "scan-completed",
		Timestamp: timestamp,
		Registry:  registryInfo,
		Data: &webhook.ScanCompletedData{
			ImagesScanned:   len(images),
			Vulnerabilities: vulnSummary,
		},
	}
}

// buildVulnerabilityCriticalPayload creates a vulnerability-critical event payload.
// Returns nil if no critical vulnerabilities are found.
func buildVulnerabilityCriticalPayload(
	timestamp string,
	registryInfo webhook.RegistryInfo,
	images []v1alpha1.ImageInfo,
) *webhook.Payload {
	affectedImages := make([]webhook.AffectedImage, 0, len(images))

	for _, img := range images {
		if img.Vulnerabilities == nil || img.Vulnerabilities.Critical == 0 {
			continue
		}

		var topCVEs []string
		for _, cve := range img.Vulnerabilities.TopCVEs {
			if cve.Severity == "CRITICAL" {
				topCVEs = append(topCVEs, cve.ID)
			}
		}

		affectedImages = append(affectedImages, webhook.AffectedImage{
			Tag:           img.Tag,
			Digest:        img.Digest,
			CriticalCount: img.Vulnerabilities.Critical,
			TopCVEs:       topCVEs,
		})
	}

	if len(affectedImages) == 0 {
		return nil
	}

	return &webhook.Payload{
		Event:     "vulnerability-critical",
		Timestamp: timestamp,
		Registry:  registryInfo,
		Data: &webhook.VulnerabilityCriticalData{
			AffectedImages: affectedImages,
		},
	}
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}
