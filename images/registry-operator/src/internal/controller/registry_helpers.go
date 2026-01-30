package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// Default configuration values.
const (
	_defaultScanInterval           = 300
	_defaultTimeout                = 30 * time.Second
	_defaultRetryAttempts          = 3
	_defaultRetryDelay             = 5 * time.Second
	_defaultConcurrency            = 1
	_defaultVulnScanInterval       = 3600
	_defaultSBOMScanInterval       = 3600
	_defaultProvenanceScanInterval = 3600
	_defaultWebhookTimeout         = 10 * time.Second
)

// resolvedScanConfig holds resolved scan configuration values.
type resolvedScanConfig struct {
	timeout       time.Duration
	retryAttempts int
	retryDelay    time.Duration
	concurrency   int
}

// getScanConfig resolves scan configuration from Registry spec with defaults.
func (r *RegistryReconciler) getScanConfig(reg *v1alpha1.Registry) resolvedScanConfig {
	cfg := resolvedScanConfig{
		timeout:       _defaultTimeout,
		retryAttempts: _defaultRetryAttempts,
		retryDelay:    _defaultRetryDelay,
		concurrency:   _defaultConcurrency,
	}

	if reg.Spec.ScanConfig == nil {
		return cfg
	}

	sc := reg.Spec.ScanConfig

	if sc.Timeout != "" {
		if d, err := time.ParseDuration(sc.Timeout); err == nil {
			cfg.timeout = d
		}
	}

	if sc.RetryAttempts > 0 {
		cfg.retryAttempts = sc.RetryAttempts
	}

	if sc.RetryDelay != "" {
		if d, err := time.ParseDuration(sc.RetryDelay); err == nil {
			cfg.retryDelay = d
		}
	}

	if sc.Concurrency > 0 {
		cfg.concurrency = sc.Concurrency
	}

	return cfg
}

// withRetry executes fn with retry logic based on config.
func (r *RegistryReconciler) withRetry(cfg resolvedScanConfig, fn func() error) error {
	var lastErr error
	for attempt := range cfg.retryAttempts {
		if err := fn(); err != nil {
			lastErr = err
			if attempt < cfg.retryAttempts-1 {
				time.Sleep(cfg.retryDelay)
			}
			continue
		}
		return nil
	}
	return lastErr
}

// getRequeueInterval returns the requeue interval for the Registry.
func (r *RegistryReconciler) getRequeueInterval(reg *v1alpha1.Registry) time.Duration {
	interval := reg.Spec.ScanInterval
	if interval <= 0 {
		interval = _defaultScanInterval
	}
	return time.Duration(interval) * time.Second
}

// getCredentials retrieves registry credentials from a Secret.
func (r *RegistryReconciler) getCredentials(ctx context.Context, reg *v1alpha1.Registry) (username, password string, err error) {
	secretRef := reg.Spec.CredentialsSecret
	if secretRef == nil {
		return "", "", nil
	}

	secretKey := types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: reg.Namespace,
	}

	var secret corev1.Secret
	if err := r.client.Get(ctx, secretKey, &secret); err != nil {
		return "", "", fmt.Errorf("get secret %s: %w", secretRef.Name, err)
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

// extractTags extracts tag names from image list.
func extractTags(images []v1alpha1.ImageInfo) []string {
	tags := make([]string, 0, len(images))
	for _, img := range images {
		tags = append(tags, img.Tag)
	}
	return tags
}

// buildImageRef constructs a full image reference from registry URL, repository, and tag.
func buildImageRef(registryURL, repository, tag string) string {
	host := strings.TrimPrefix(registryURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	return fmt.Sprintf("%s/%s:%s", host, repository, tag)
}

// buildImageRefWithDigest constructs a full image reference using digest.
func buildImageRefWithDigest(registryURL, repository, digest string) string {
	host := strings.TrimPrefix(registryURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	return fmt.Sprintf("%s/%s@%s", host, repository, digest)
}
