package controller

import (
	"context"
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
	"registry-operator/internal/drift"
	"registry-operator/internal/provenance"
	"registry-operator/internal/sbom"
	"registry-operator/internal/vulnerability"
)

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

	tagsToScan := getTagsToScanVuln(vulnConfig, images)

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

// getTagsToScanVuln returns the list of tags to scan for vulnerabilities.
func getTagsToScanVuln(vulnConfig *v1alpha1.VulnerabilityScanConfig, images []v1alpha1.ImageInfo) []string {
	if len(vulnConfig.Tags) > 0 {
		return vulnConfig.Tags
	}
	return extractTags(images)
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

	tagsToScan := getTagsToScanSBOM(sbomConfig, images)

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
func getTagsToScanSBOM(sbomConfig *v1alpha1.SBOMConfig, images []v1alpha1.ImageInfo) []string {
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

	scanner := newProvenanceScanner(username, password)
	tagsToScan := getTagsToScanProvenance(provConfig, images)

	logger.Info("starting provenance scan",
		"registry", reg.Spec.URL,
		"repository", reg.Spec.Repository,
		"tagsToScan", len(tagsToScan),
	)

	for i, img := range images {
		if !slices.Contains(tagsToScan, img.Tag) {
			continue
		}

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

// newProvenanceScanner creates a provenance scanner with authentication.
func newProvenanceScanner(username, password string) *provenance.Scanner {
	auth := authn.Anonymous
	if username != "" {
		auth = authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
	}
	return provenance.NewScanner(provenance.Config{
		Auth:    auth,
		Timeout: 30 * time.Second,
	})
}

// getTagsToScanProvenance returns the list of tags to scan for provenance.
func getTagsToScanProvenance(provConfig *v1alpha1.ProvenanceConfig, images []v1alpha1.ImageInfo) []string {
	if len(provConfig.Tags) > 0 {
		return provConfig.Tags
	}
	return extractTags(images)
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
