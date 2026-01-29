// Package drift provides drift detection functionality.
package drift

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// Status constants for workload drift status.
const (
	StatusLatest     = "LATEST"
	StatusOutdated   = "OUTDATED"
	StatusVulnerable = "VULNERABLE"
	StatusUnknown    = "UNKNOWN"
)

// Recommendation constants for update recommendations.
const (
	RecommendationNoAction          = "NO_ACTION"
	RecommendationUpdateAvailable   = "UPDATE_AVAILABLE"
	RecommendationUpdateRecommended = "UPDATE_RECOMMENDED"
	RecommendationUrgentUpdate      = "URGENT_UPDATE"
	RecommendationReviewRequired    = "REVIEW_REQUIRED"
	RecommendationCaution           = "CAUTION"
	RecommendationAvailable         = "AVAILABLE"
	RecommendationRecommended       = "RECOMMENDED"
)

const _maxUpdatesInStatus = 5

// _recommendationPriority defines the sort order for update recommendations.
var _recommendationPriority = map[string]int{
	RecommendationUrgentUpdate: 0,
	RecommendationRecommended:  1,
	RecommendationAvailable:    2,
	RecommendationCaution:      3,
}

// AnalyzeDrift compares running workloads with available images in registry.
func AnalyzeDrift(
	workloads []WorkloadImage,
	availableImages []v1alpha1.ImageInfo,
) *v1alpha1.DriftStatus {
	now := metav1.Now()
	driftStatus := &v1alpha1.DriftStatus{
		LastCheckTime: &now,
		Workloads:     make([]v1alpha1.WorkloadDrift, 0, len(workloads)),
		Summary:       &v1alpha1.DriftSummary{},
	}

	imageMap := buildImageMap(availableImages)

	for _, wl := range workloads {
		drift := analyzeWorkload(wl, imageMap, availableImages)
		driftStatus.Workloads = append(driftStatus.Workloads, drift)

		driftStatus.Summary.Total++
		switch drift.Status {
		case StatusLatest:
			driftStatus.Summary.Latest++
		case StatusOutdated:
			driftStatus.Summary.Outdated++
		case StatusVulnerable:
			driftStatus.Summary.Vulnerable++
			if strings.Contains(drift.Recommendation, "URGENT") {
				driftStatus.Summary.UrgentUpdates++
			}
		case StatusUnknown:
			driftStatus.Summary.Unknown++
		}
	}

	return driftStatus
}

// analyzeWorkload analyzes a single workload for drift.
func analyzeWorkload(
	wl WorkloadImage,
	imageMap map[string]*v1alpha1.ImageInfo,
	availableImages []v1alpha1.ImageInfo,
) v1alpha1.WorkloadDrift {
	drift := v1alpha1.WorkloadDrift{
		Namespace:    wl.Namespace,
		Name:         wl.Name,
		Kind:         wl.Kind,
		CurrentImage: wl.Image,
		CurrentTag:   wl.Tag,
	}

	currentInfo, found := imageMap[wl.Tag]
	if !found {
		drift.Status = StatusUnknown
		drift.Recommendation = RecommendationReviewRequired
		drift.Message = fmt.Sprintf("Image tag %s not found in registry", wl.Tag)
		return drift
	}

	hasCritical := currentInfo.Vulnerabilities != nil && currentInfo.Vulnerabilities.Critical > 0
	updates := findAvailableUpdates(wl.Tag, currentInfo, availableImages)
	drift.AvailableUpdates = updates

	// No updates available
	if len(updates) == 0 {
		if hasCritical {
			drift.Status = StatusVulnerable
			drift.Recommendation = RecommendationUrgentUpdate
			drift.Message = fmt.Sprintf("Current image has %d Critical CVEs but no newer version available",
				currentInfo.Vulnerabilities.Critical)
			return drift
		}

		drift.Status = StatusLatest
		drift.Recommendation = RecommendationNoAction
		drift.Message = "Using latest available version"
		return drift
	}

	// Has updates - check if current has critical vulnerabilities
	if hasCritical {
		drift.Status = StatusVulnerable
		drift.Recommendation = RecommendationUrgentUpdate
		drift.Message = fmt.Sprintf("Current image has %d Critical CVEs. Update available.",
			currentInfo.Vulnerabilities.Critical)
		return drift
	}

	// Outdated - check if updates have important fixes
	drift.Status = StatusOutdated
	for _, update := range updates {
		if update.CriticalCVEsFixed > 0 || update.HighCVEsFixed > 0 {
			drift.Recommendation = RecommendationUpdateRecommended
			drift.Message = "Newer version with security fixes available"
			return drift
		}
	}

	drift.Recommendation = RecommendationUpdateAvailable
	drift.Message = "Newer version available (no critical fixes)"
	return drift
}

// isNewerVersion compares two version tags using semantic versioning.
// Returns true if candidateTag is newer than currentTag.
// Returns false if versions cannot be parsed as semver.
func isNewerVersion(currentTag, candidateTag string) bool {
	currentVer, err1 := semver.NewVersion(currentTag)
	candidateVer, err2 := semver.NewVersion(candidateTag)

	if err1 != nil || err2 != nil {
		// If either tag is not a valid semver, cannot determine if newer
		return false
	}

	return candidateVer.GreaterThan(currentVer)
}

// findAvailableUpdates finds newer versions of the image.
func findAvailableUpdates(
	currentTag string,
	currentInfo *v1alpha1.ImageInfo,
	availableImages []v1alpha1.ImageInfo,
) []v1alpha1.AvailableUpdate {
	updates := make([]v1alpha1.AvailableUpdate, 0, len(availableImages))

	for _, img := range availableImages {
		if img.Tag == currentTag {
			continue
		}

		update := buildUpdateInfo(currentTag, currentInfo, img)
		if shouldIncludeUpdate(update) {
			updates = append(updates, update)
		}
	}

	sortUpdates(updates)

	if len(updates) > _maxUpdatesInStatus {
		return updates[:_maxUpdatesInStatus]
	}

	return updates
}

// buildUpdateInfo creates an AvailableUpdate with all calculated fields.
func buildUpdateInfo(currentTag string, currentInfo *v1alpha1.ImageInfo, img v1alpha1.ImageInfo) v1alpha1.AvailableUpdate {
	update := v1alpha1.AvailableUpdate{
		Tag:   img.Tag,
		Newer: isNewerVersion(currentTag, img.Tag),
	}

	calculateCVEDiff(&update, currentInfo.Vulnerabilities, img.Vulnerabilities)
	calculateSizeDiff(&update, currentInfo.Size, img.Size)
	update.Recommendation = calculateRecommendation(update)

	return update
}

// calculateCVEDiff calculates CVE fixes and new CVEs between versions.
func calculateCVEDiff(update *v1alpha1.AvailableUpdate, current, candidate *v1alpha1.VulnerabilitySummary) {
	if current == nil || candidate == nil {
		return
	}

	if candidate.Critical < current.Critical {
		update.CriticalCVEsFixed = current.Critical - candidate.Critical
	} else if candidate.Critical > current.Critical {
		update.NewCVEs = candidate.Critical - current.Critical
	}

	if candidate.High < current.High {
		update.HighCVEsFixed = current.High - candidate.High
	}
}

// calculateSizeDiff calculates size difference between images.
func calculateSizeDiff(update *v1alpha1.AvailableUpdate, currentSize, newSize int64) {
	if currentSize > 0 && newSize > 0 {
		update.SizeDiff = newSize - currentSize
	}
}

// calculateRecommendation determines update recommendation based on CVE fixes.
func calculateRecommendation(update v1alpha1.AvailableUpdate) string {
	switch {
	case update.CriticalCVEsFixed > 0:
		return RecommendationUrgentUpdate
	case update.HighCVEsFixed > 0:
		return RecommendationRecommended
	case update.NewCVEs > 0:
		return RecommendationCaution
	default:
		return RecommendationAvailable
	}
}

// shouldIncludeUpdate checks if update should be included in results.
func shouldIncludeUpdate(update v1alpha1.AvailableUpdate) bool {
	hasSecurityImprovement := update.CriticalCVEsFixed > 0 || update.HighCVEsFixed > 0
	return update.Newer || hasSecurityImprovement
}

// buildImageMap creates a map of tag -> ImageInfo for quick lookup.
func buildImageMap(images []v1alpha1.ImageInfo) map[string]*v1alpha1.ImageInfo {
	m := make(map[string]*v1alpha1.ImageInfo, len(images))
	for i := range images {
		m[images[i].Tag] = &images[i]
	}
	return m
}

// sortUpdates sorts updates by recommendation priority in-place.
func sortUpdates(updates []v1alpha1.AvailableUpdate) {
	slices.SortFunc(updates, func(a, b v1alpha1.AvailableUpdate) int {
		pa := _recommendationPriority[a.Recommendation]
		pb := _recommendationPriority[b.Recommendation]
		return pa - pb
	})
}
