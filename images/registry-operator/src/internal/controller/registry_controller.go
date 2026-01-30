// Package controller implements the Registry controller.
package controller

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/go-containerregistry/pkg/authn"

	"registry-operator/internal/drift"
	"registry-operator/internal/provenance"
	"registry-operator/internal/registry"
	"registry-operator/internal/sbom"
	"registry-operator/internal/vulnerability"

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
	_registryFinalizer             = "registry.kubecontroller.io/finalizer"
)

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

// scanRegistry scans the registry for image tags and details.
func (r *RegistryReconciler) scanRegistry(ctx context.Context, reg *v1alpha1.Registry) ([]v1alpha1.ImageInfo, error) {
	logger := log.FromContext(ctx)

	username, password, err := r.getCredentials(ctx, reg)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	scanCfg := r.getScanConfig(reg)

	regClient := registry.NewClient(
		reg.Spec.URL,
		username,
		password,
		reg.Spec.InsecureSkipVerify,
		registry.WithTimeout(scanCfg.timeout),
	)

	var tags []string
	err = r.withRetry(scanCfg, func() error {
		var retryErr error
		tags, retryErr = regClient.ListTags(ctx, reg.Spec.Repository)
		return retryErr
	})
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	tags, err = r.filterTags(tags, reg.Spec.TagFilter)
	if err != nil {
		return nil, fmt.Errorf("filter tags: %w", err)
	}

	return r.fetchImageDetails(ctx, logger, regClient, reg.Spec.Repository, tags, scanCfg)
}

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

// filterTags filters and sorts tags based on TagFilter configuration.
func (r *RegistryReconciler) filterTags(tags []string, filter *v1alpha1.TagFilter) ([]string, error) {
	if filter == nil {
		return tags, nil
	}

	var (
		includeRegex *regexp.Regexp
		excludeRegex *regexp.Regexp
		err          error
	)

	if filter.Include != "" {
		includeRegex, err = regexp.Compile(filter.Include)
		if err != nil {
			return nil, fmt.Errorf("compile include pattern %q: %w", filter.Include, err)
		}
	}

	if filter.Exclude != "" {
		excludeRegex, err = regexp.Compile(filter.Exclude)
		if err != nil {
			return nil, fmt.Errorf("compile exclude pattern %q: %w", filter.Exclude, err)
		}
	}

	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		if includeRegex != nil && !includeRegex.MatchString(tag) {
			continue
		}
		if excludeRegex != nil && excludeRegex.MatchString(tag) {
			continue
		}
		result = append(result, tag)
	}

	switch filter.SortBy {
	case "newest":
		sort.Sort(sort.Reverse(sort.StringSlice(result)))
	case "oldest", "alphabetical", "":
		sort.Strings(result)
	}

	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

// fetchImageDetails fetches details for all tags using worker pool pattern.
// Concurrency is controlled by cfg.concurrency (defaults to 1).
func (r *RegistryReconciler) fetchImageDetails(
	ctx context.Context,
	logger logr.Logger,
	regClient *registry.Client,
	repository string,
	tags []string,
	cfg resolvedScanConfig,
) ([]v1alpha1.ImageInfo, error) {
	if len(tags) == 0 {
		return nil, nil
	}

	type job struct {
		index int
		tag   string
	}

	results := make([]v1alpha1.ImageInfo, len(tags))
	jobs := make(chan job, len(tags))

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check context before processing
				if ctx.Err() != nil {
					results[j.index] = v1alpha1.ImageInfo{Tag: j.tag}
					continue
				}
				results[j.index] = r.fetchSingleImageDetails(ctx, logger, regClient, repository, j.tag, cfg)
			}
		}()
	}

	// Send jobs to workers
	for i, tag := range tags {
		select {
		case jobs <- job{index: i, tag: tag}:
		case <-ctx.Done():
			// Context canceled, close jobs and let workers drain
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)

	wg.Wait()
	return results, nil
}

// fetchSingleImageDetails fetches details for a single image tag with retry logic.
func (r *RegistryReconciler) fetchSingleImageDetails(
	ctx context.Context,
	logger logr.Logger,
	regClient *registry.Client,
	repository, tag string,
	cfg resolvedScanConfig,
) v1alpha1.ImageInfo {
	info := v1alpha1.ImageInfo{Tag: tag}

	err := r.withRetry(cfg, func() error {
		details, err := regClient.GetImageDetails(ctx, repository, tag)
		if err != nil {
			return err
		}
		info.Digest = details.Digest
		info.Size = details.Size
		return nil
	})
	if err != nil {
		logger.V(1).Info("get image details: failed", "tag", tag, "error", err)
	}

	return info
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

// handleScanFailure updates status with failure information.
func (r *RegistryReconciler) handleScanFailure(ctx context.Context, reg *v1alpha1.Registry, scanErr error) (ctrl.Result, error) {
	if err := r.updateStatusFailed(ctx, reg, scanErr.Error()); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, scanErr
}

// updateStatusSuccess updates Registry status with successful scan results.
func (r *RegistryReconciler) updateStatusSuccess(ctx context.Context, reg *v1alpha1.Registry, images []v1alpha1.ImageInfo, driftStatus *v1alpha1.DriftStatus) error {
	return r.updateStatus(ctx, reg, "Success", "", images, driftStatus)
}

// updateStatusFailed updates Registry status with failure information.
func (r *RegistryReconciler) updateStatusFailed(ctx context.Context, reg *v1alpha1.Registry, message string) error {
	return r.updateStatus(ctx, reg, "Failed", message, nil, nil)
}

// updateStatus updates the Registry status subresource.
func (r *RegistryReconciler) updateStatus(ctx context.Context, reg *v1alpha1.Registry, scanStatus, message string, images []v1alpha1.ImageInfo, driftStatus *v1alpha1.DriftStatus) error {
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

// getRequeueInterval returns the requeue interval for the Registry.
func (r *RegistryReconciler) getRequeueInterval(reg *v1alpha1.Registry) time.Duration {
	interval := reg.Spec.ScanInterval
	if interval <= 0 {
		interval = _defaultScanInterval
	}
	return time.Duration(interval) * time.Second
}

// shouldScanVulnerabilities checks if vulnerability scanning should be performed.
func (r *RegistryReconciler) shouldScanVulnerabilities(reg *v1alpha1.Registry) bool {
	vulnConfig := reg.Spec.VulnerabilityScanning
	if vulnConfig == nil || !vulnConfig.Enabled {
		return false
	}

	vulnInterval := vulnConfig.ScanInterval
	if vulnInterval <= 0 {
		vulnInterval = _defaultVulnScanInterval
	}

	for _, img := range reg.Status.Images {
		if img.Vulnerabilities == nil || img.Vulnerabilities.LastScanTime == nil {
			continue
		}
		elapsed := time.Since(img.Vulnerabilities.LastScanTime.Time)
		if elapsed < time.Duration(vulnInterval)*time.Second {
			return false
		}
	}

	return true
}

// scanVulnerabilities scans images for vulnerabilities using Trivy.
func (r *RegistryReconciler) scanVulnerabilities(
	ctx context.Context,
	logger logr.Logger,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
) []v1alpha1.ImageInfo {
	vulnConfig := reg.Spec.VulnerabilityScanning
	if vulnConfig == nil {
		return images
	}

	if err := vulnerability.CheckTrivyInstalled(); err != nil {
		logger.Error(err, "trivy not available, skipping vulnerability scan")
		return images
	}

	scanner := vulnerability.NewTrivyScanner(vulnerability.TrivyConfig{
		SeverityThreshold: vulnConfig.SeverityThreshold,
		IgnoreUnfixed:     vulnConfig.IgnoreUnfixed,
		Timeout:           5 * time.Minute,
	})

	tagsToScan := r.getTagsToScan(vulnConfig, images)

	logger.Info("starting vulnerability scan",
		"registry", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"tagsToScan", len(tagsToScan),
	)

	for i, img := range images {
		if !slices.Contains(tagsToScan, img.Tag) {
			continue
		}

		imageRef := buildImageRef(reg.Spec.URL, reg.Spec.Repository, img.Tag)
		logger.V(1).Info("scanning image for vulnerabilities", "image", imageRef)

		summary, err := scanner.Scan(ctx, imageRef)
		if err != nil {
			logger.Error(err, "scan image for vulnerabilities: failed", "image", imageRef)
			continue
		}

		images[i].Vulnerabilities = summary

		logger.Info("vulnerability scan completed",
			"image", imageRef,
			"critical", summary.Critical,
			"high", summary.High,
			"medium", summary.Medium,
			"low", summary.Low,
			"total", summary.Total,
		)
	}

	return images
}

// getTagsToScan returns the list of tags to scan for vulnerabilities.
func (r *RegistryReconciler) getTagsToScan(vulnConfig *v1alpha1.VulnerabilityScanConfig, images []v1alpha1.ImageInfo) []string {
	if len(vulnConfig.Tags) > 0 {
		return vulnConfig.Tags
	}
	return extractTags(images)
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

// shouldScanSBOM checks if SBOM scanning should be performed.
func (r *RegistryReconciler) shouldScanSBOM(reg *v1alpha1.Registry) bool {
	sbomConfig := reg.Spec.SBOMGeneration
	if sbomConfig == nil || !sbomConfig.Enabled {
		return false
	}

	sbomInterval := sbomConfig.ScanInterval
	if sbomInterval <= 0 {
		sbomInterval = _defaultSBOMScanInterval
	}

	for _, img := range reg.Status.Images {
		if img.SBOM == nil || img.SBOM.GeneratedAt == nil {
			return true
		}
		elapsed := time.Since(img.SBOM.GeneratedAt.Time)
		if elapsed >= time.Duration(sbomInterval)*time.Second {
			return true
		}
	}

	return false
}

// scanSBOM generates SBOM for images using Syft.
func (r *RegistryReconciler) scanSBOM(
	ctx context.Context,
	logger logr.Logger,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
) []v1alpha1.ImageInfo {
	sbomConfig := reg.Spec.SBOMGeneration
	if sbomConfig == nil {
		return images
	}

	if err := sbom.CheckSyftInstalled(); err != nil {
		logger.Error(err, "syft not available, skipping SBOM generation")
		return images
	}

	scanner := sbom.NewScanner(sbom.SyftConfig{
		Format:  sbomConfig.Format,
		Timeout: 5 * time.Minute,
	})

	analyzer := sbom.NewAnalyzer()

	tagsToScan := r.getTagsToScanSBOM(sbomConfig, images)

	logger.Info("starting SBOM generation",
		"registry", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"tagsToScan", len(tagsToScan),
	)

	for i, img := range images {
		if !slices.Contains(tagsToScan, img.Tag) {
			continue
		}

		imageRef := buildImageRef(reg.Spec.URL, reg.Spec.Repository, img.Tag)
		logger.V(1).Info("generating SBOM for image", "image", imageRef)

		sbomInfo, err := scanner.Scan(ctx, imageRef)
		if err != nil {
			logger.Error(err, "generate SBOM: failed", "image", imageRef)
			continue
		}

		analyzer.AnalyzeDependencies(sbomInfo)

		if img.Vulnerabilities != nil {
			analyzer.EnrichWithVulnerabilities(sbomInfo, img.Vulnerabilities)
		}

		images[i].SBOM = sbomInfo

		logger.Info("SBOM generation completed",
			"image", imageRef,
			"totalPackages", sbomInfo.TotalPackages,
			"packageTypes", len(sbomInfo.PackageTypes),
		)
	}

	return images
}

// getTagsToScanSBOM returns the list of tags to generate SBOM for.
func (r *RegistryReconciler) getTagsToScanSBOM(sbomConfig *v1alpha1.SBOMConfig, images []v1alpha1.ImageInfo) []string {
	if len(sbomConfig.Tags) > 0 {
		return sbomConfig.Tags
	}
	return extractTags(images)
}

// shouldScanProvenance checks if provenance scanning should be performed.
func (r *RegistryReconciler) shouldScanProvenance(reg *v1alpha1.Registry) bool {
	provConfig := reg.Spec.ProvenanceTracking
	if provConfig == nil || !provConfig.Enabled {
		return false
	}

	provInterval := provConfig.ScanInterval
	if provInterval <= 0 {
		provInterval = _defaultProvenanceScanInterval
	}

	for _, img := range reg.Status.Images {
		if img.Provenance == nil || img.Provenance.LastCheckTime == nil {
			return true
		}
		elapsed := time.Since(img.Provenance.LastCheckTime.Time)
		if elapsed >= time.Duration(provInterval)*time.Second {
			return true
		}
	}

	return false
}

// scanProvenance scans images for provenance attestations.
func (r *RegistryReconciler) scanProvenance(
	ctx context.Context,
	logger logr.Logger,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
	username, password string,
) []v1alpha1.ImageInfo {
	provConfig := reg.Spec.ProvenanceTracking
	if provConfig == nil {
		return images
	}

	auth := authn.Anonymous
	if username != "" {
		auth = authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
	}

	scanner := provenance.NewScanner(provenance.Config{
		Auth:    auth,
		Timeout: 30 * time.Second,
	})

	tagsToScan := r.getTagsToScanProvenance(provConfig, images)

	logger.Info("starting provenance scan",
		"registry", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"tagsToScan", len(tagsToScan),
	)

	for i, img := range images {
		if !slices.Contains(tagsToScan, img.Tag) {
			continue
		}

		// Provenance requires digest reference
		if img.Digest == "" {
			logger.V(1).Info("skipping provenance scan: no digest", "tag", img.Tag)
			continue
		}

		imageRef := buildImageRefWithDigest(reg.Spec.URL, reg.Spec.Repository, img.Digest)
		logger.V(1).Info("scanning image for provenance", "image", imageRef)

		provInfo, err := scanner.Scan(ctx, imageRef)
		if err != nil {
			logger.Error(err, "scan image for provenance: failed", "image", imageRef)
			continue
		}

		images[i].Provenance = provInfo

		logger.Info("provenance scan completed",
			"image", imageRef,
			"builder", provInfo.Builder,
			"slsaLevel", provInfo.SLSALevel,
			"signed", provInfo.Signed,
		)
	}

	return images
}

// getTagsToScanProvenance returns the list of tags to scan for provenance.
func (r *RegistryReconciler) getTagsToScanProvenance(provConfig *v1alpha1.ProvenanceConfig, images []v1alpha1.ImageInfo) []string {
	if len(provConfig.Tags) > 0 {
		return provConfig.Tags
	}
	return extractTags(images)
}

// buildImageRefWithDigest constructs a full image reference using digest.
func buildImageRefWithDigest(registryURL, repository, digest string) string {
	host := strings.TrimPrefix(registryURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	return fmt.Sprintf("%s/%s@%s", host, repository, digest)
}

// shouldDetectDrift checks if drift detection should run.
func (r *RegistryReconciler) shouldDetectDrift(reg *v1alpha1.Registry) bool {
	driftConfig := reg.Spec.DriftDetection
	if driftConfig == nil || !driftConfig.Enabled {
		return false
	}

	checkInterval := driftConfig.CheckInterval
	if checkInterval <= 0 {
		checkInterval = reg.Spec.ScanInterval
		if checkInterval <= 0 {
			checkInterval = _defaultScanInterval
		}
	}

	if reg.Status.Drift == nil || reg.Status.Drift.LastCheckTime == nil {
		return true
	}

	elapsed := time.Since(reg.Status.Drift.LastCheckTime.Time)
	return elapsed >= time.Duration(checkInterval)*time.Second
}

// detectDrift detects drift between running workloads and available images.
func (r *RegistryReconciler) detectDrift(
	ctx context.Context,
	logger logr.Logger,
	reg *v1alpha1.Registry,
	images []v1alpha1.ImageInfo,
) *v1alpha1.DriftStatus {
	driftConfig := reg.Spec.DriftDetection
	if driftConfig == nil {
		return nil
	}

	logger.Info("detecting drift",
		"registry", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"namespaces", driftConfig.Namespaces,
	)

	scanner := drift.NewScanner(r.client)

	workloads, err := scanner.ScanWorkloads(ctx, reg.Spec.Repository, driftConfig)
	if err != nil {
		logger.Error(err, "scan workloads failed")
		return nil
	}

	logger.V(1).Info("found workloads", "count", len(workloads))

	driftStatus := drift.AnalyzeDrift(workloads, images)

	logger.Info("drift detection complete",
		"total", driftStatus.Summary.Total,
		"latest", driftStatus.Summary.Latest,
		"outdated", driftStatus.Summary.Outdated,
		"vulnerable", driftStatus.Summary.Vulnerable,
		"urgentUpdates", driftStatus.Summary.UrgentUpdates,
	)

	return driftStatus
}

// SetupRegistryController sets up the Registry controller with the Manager.
func SetupRegistryController(mgr ctrl.Manager) error {
	reconciler := newRegistryReconciler(mgr)
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Registry{}).
		Complete(reconciler)
}
