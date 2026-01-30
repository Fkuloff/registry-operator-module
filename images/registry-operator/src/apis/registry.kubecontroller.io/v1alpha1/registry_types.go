// Package v1alpha1 contains API Schema definitions for the registry v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegistrySpec defines the desired state of Registry.
type RegistrySpec struct {
	// URL is the registry URL (e.g., "https://registry-1.docker.io").
	URL string `json:"url"`

	// Repository is the repository to scan (e.g., "library/nginx").
	Repository string `json:"repository"`

	// ScanInterval is the interval between scans in seconds.
	// +optional
	ScanInterval int64 `json:"scanInterval,omitempty"`

	// CredentialsSecret is a reference to a Secret containing registry credentials.
	// +optional
	CredentialsSecret *SecretReference `json:"credentialsSecret,omitempty"`

	// InsecureSkipVerify skips TLS certificate verification.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// ScanConfig defines dynamic scan settings.
	// +optional
	ScanConfig *ScanConfig `json:"scanConfig,omitempty"`

	// TagFilter defines filtering rules for tags.
	// +optional
	TagFilter *TagFilter `json:"tagFilter,omitempty"`

	// VulnerabilityScanning defines vulnerability scanning settings.
	// +optional
	VulnerabilityScanning *VulnerabilityScanConfig `json:"vulnerabilityScanning,omitempty"`

	// SBOMGeneration defines SBOM generation settings.
	// +optional
	SBOMGeneration *SBOMConfig `json:"sbomGeneration,omitempty"`

	// DriftDetection defines drift detection settings.
	// +optional
	DriftDetection *DriftDetectionConfig `json:"driftDetection,omitempty"`

	// ProvenanceTracking defines provenance tracking settings.
	// +optional
	ProvenanceTracking *ProvenanceConfig `json:"provenanceTracking,omitempty"`

	// Webhook defines webhook notification settings.
	// +optional
	Webhook *WebhookConfig `json:"webhook,omitempty"`
}

// ProvenanceConfig defines provenance tracking settings.
type ProvenanceConfig struct {
	// Enabled enables provenance tracking.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// ScanInterval is the interval between provenance checks in seconds.
	// Defaults to 3600 (1 hour).
	// +optional
	ScanInterval int64 `json:"scanInterval,omitempty"`

	// Tags specifies which tags to check provenance for. If empty, all tags are processed.
	// +optional
	Tags []string `json:"tags,omitempty"`
}

// SBOMConfig defines SBOM generation settings.
type SBOMConfig struct {
	// Enabled enables SBOM generation.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Format specifies the SBOM format: "spdx-json", "cyclonedx-json", "syft-json".
	// Defaults to "syft-json".
	// +optional
	Format string `json:"format,omitempty"`

	// ScanInterval is the interval between SBOM scans in seconds.
	// Typically matches vulnerability scan interval.
	// +optional
	ScanInterval int64 `json:"scanInterval,omitempty"`

	// Tags specifies which tags to generate SBOM for. If empty, all tags are processed.
	// +optional
	Tags []string `json:"tags,omitempty"`
}

// VulnerabilityScanConfig defines vulnerability scanning settings.
type VulnerabilityScanConfig struct {
	// Enabled enables vulnerability scanning.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Scanner specifies which scanner to use. Currently only "trivy" is supported.
	// +optional
	Scanner string `json:"scanner,omitempty"`

	// ScanInterval is the interval between vulnerability scans in seconds.
	// Typically longer than tag scan interval.
	// +optional
	ScanInterval int64 `json:"scanInterval,omitempty"`

	// SeverityThreshold is the minimum severity to report.
	// Valid values: "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN".
	// +optional
	SeverityThreshold string `json:"severityThreshold,omitempty"`

	// IgnoreUnfixed ignores vulnerabilities without a fix.
	// +optional
	IgnoreUnfixed bool `json:"ignoreUnfixed,omitempty"`

	// Tags specifies which tags to scan. If empty, all tags are scanned.
	// +optional
	Tags []string `json:"tags,omitempty"`
}

// ScanConfig defines dynamic scan settings.
type ScanConfig struct {
	// Timeout is the HTTP request timeout (e.g., "30s", "1m").
	// +optional
	Timeout string `json:"timeout,omitempty"`

	// RetryAttempts is the number of retry attempts on failure.
	// +optional
	RetryAttempts int `json:"retryAttempts,omitempty"`

	// RetryDelay is the delay between retry attempts (e.g., "5s", "10s").
	// +optional
	RetryDelay string `json:"retryDelay,omitempty"`

	// Concurrency is the number of concurrent requests when fetching image details.
	// +optional
	Concurrency int `json:"concurrency,omitempty"`
}

// TagFilter defines filtering rules for tags.
type TagFilter struct {
	// Include is a regex pattern for tags to include.
	// +optional
	Include string `json:"include,omitempty"`

	// Exclude is a regex pattern for tags to exclude.
	// +optional
	Exclude string `json:"exclude,omitempty"`

	// Limit is the maximum number of tags to return. Zero means unlimited.
	// +optional
	Limit int `json:"limit,omitempty"`

	// SortBy specifies the sort order: "newest", "oldest", "alphabetical".
	// +optional
	SortBy string `json:"sortBy,omitempty"`
}

// SecretReference references a Secret containing registry credentials.
type SecretReference struct {
	// Name is the name of the Secret.
	Name string `json:"name"`

	// UsernameKey is the key in the Secret containing the username.
	// Defaults to "username".
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// PasswordKey is the key in the Secret containing the password.
	// Defaults to "password".
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// RegistryStatus defines the observed state of Registry.
type RegistryStatus struct {
	// LastScanTime is the timestamp of the last scan.
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// LastScanStatus is the status of the last scan: "Success" or "Failed".
	// +optional
	LastScanStatus string `json:"lastScanStatus,omitempty"`

	// Message contains error details when LastScanStatus is "Failed".
	// +optional
	Message string `json:"message,omitempty"`

	// Images contains information about discovered images.
	// +optional
	Images []ImageInfo `json:"images,omitempty"`

	// Drift contains drift detection results.
	// +optional
	Drift *DriftStatus `json:"drift,omitempty"`

	// Webhook contains webhook notification status.
	// +optional
	Webhook *WebhookStatus `json:"webhook,omitempty"`
}

// ImageInfo contains information about a single image tag.
type ImageInfo struct {
	// Tag is the image tag.
	Tag string `json:"tag"`

	// Digest is the image digest (SHA256).
	// +optional
	Digest string `json:"digest,omitempty"`

	// Size is the total image size in bytes.
	// +optional
	Size int64 `json:"size,omitempty"`

	// Timestamps contains temporal information about the image.
	// +optional
	Timestamps *ImageTimestamps `json:"timestamps,omitempty"`

	// Platforms lists the OS/architecture combinations this image supports.
	// +optional
	Platforms []string `json:"platforms,omitempty"`

	// Config contains image configuration extracted from the manifest.
	// +optional
	Config *ImageConfig `json:"config,omitempty"`

	// Usage contains information about where this image is used in the cluster.
	// +optional
	Usage *ImageUsage `json:"usage,omitempty"`

	// Vulnerabilities contains vulnerability scan results.
	// +optional
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`

	// SBOM contains Software Bill of Materials information.
	// +optional
	SBOM *SBOMInfo `json:"sbom,omitempty"`

	// Provenance contains image provenance information.
	// +optional
	Provenance *ProvenanceInfo `json:"provenance,omitempty"`
}

// ImageTimestamps contains temporal information about the image.
type ImageTimestamps struct {
	// Created is when the image was built (from image config).
	// +optional
	Created *metav1.Time `json:"created,omitempty"`

	// FirstSeen is when the operator first discovered this image.
	// +optional
	FirstSeen *metav1.Time `json:"firstSeen,omitempty"`

	// Age is a human-readable age string (e.g., "45d", "2h").
	// +optional
	Age string `json:"age,omitempty"`
}

// ImageConfig contains configuration information extracted from the image.
type ImageConfig struct {
	// BaseImage is the base image if specified in labels.
	// +optional
	BaseImage string `json:"baseImage,omitempty"`

	// Author is the image author/maintainer.
	// +optional
	Author string `json:"author,omitempty"`

	// User is the user/group the container runs as.
	// +optional
	User string `json:"user,omitempty"`

	// WorkDir is the working directory inside the container.
	// +optional
	WorkDir string `json:"workDir,omitempty"`

	// Entrypoint is the container entrypoint.
	// +optional
	Entrypoint []string `json:"entrypoint,omitempty"`

	// Cmd is the container command.
	// +optional
	Cmd []string `json:"cmd,omitempty"`

	// ExposedPorts lists the ports exposed by the image.
	// +optional
	ExposedPorts []string `json:"exposedPorts,omitempty"`

	// EnvVars lists environment variable names (values hidden for security).
	// +optional
	EnvVars []string `json:"envVars,omitempty"`

	// Labels contains OCI/Docker labels from the image.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// LayerCount is the number of layers in the image.
	// +optional
	LayerCount int `json:"layerCount,omitempty"`
}

// ImageUsage contains information about where the image is used in the cluster.
type ImageUsage struct {
	// WorkloadCount is the total number of workloads using this image.
	// +optional
	WorkloadCount int `json:"workloadCount,omitempty"`

	// Workloads lists the workloads using this image.
	// +optional
	Workloads []WorkloadReference `json:"workloads,omitempty"`

	// Namespaces lists unique namespaces where the image is used.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// TotalPods is the total number of pods running this image.
	// +optional
	TotalPods int `json:"totalPods,omitempty"`
}

// WorkloadReference identifies a workload using an image.
type WorkloadReference struct {
	// Kind is the workload kind (Deployment, StatefulSet, DaemonSet).
	Kind string `json:"kind"`

	// Namespace is the workload namespace.
	Namespace string `json:"namespace"`

	// Name is the workload name.
	Name string `json:"name"`

	// Replicas is the number of replicas (for Deployment/StatefulSet).
	// +optional
	Replicas int32 `json:"replicas,omitempty"`
}

// VulnerabilitySummary contains vulnerability scan results for an image.
type VulnerabilitySummary struct {
	// Critical is the count of critical vulnerabilities.
	// +optional
	Critical int `json:"critical,omitempty"`

	// High is the count of high severity vulnerabilities.
	// +optional
	High int `json:"high,omitempty"`

	// Medium is the count of medium severity vulnerabilities.
	// +optional
	Medium int `json:"medium,omitempty"`

	// Low is the count of low severity vulnerabilities.
	// +optional
	Low int `json:"low,omitempty"`

	// Unknown is the count of unknown severity vulnerabilities.
	// +optional
	Unknown int `json:"unknown,omitempty"`

	// Total is the total count of vulnerabilities.
	// +optional
	Total int `json:"total,omitempty"`

	// LastScanTime is the timestamp of the last vulnerability scan.
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// TopCVEs contains the top critical/high CVEs for quick reference.
	// +optional
	TopCVEs []CVEInfo `json:"topCVEs,omitempty"`
}

// CVEInfo contains details about a specific vulnerability.
type CVEInfo struct {
	// ID is the CVE identifier (e.g., "CVE-2024-1234").
	ID string `json:"id"`

	// Severity is the vulnerability severity level.
	Severity string `json:"severity"`

	// Package is the affected package name.
	Package string `json:"package"`

	// InstalledVersion is the currently installed version.
	// +optional
	InstalledVersion string `json:"installedVersion,omitempty"`

	// FixedVersion is the version that fixes the vulnerability.
	// +optional
	FixedVersion string `json:"fixedVersion,omitempty"`

	// Title is a short description of the vulnerability.
	// +optional
	Title string `json:"title,omitempty"`
}

// SBOMInfo contains Software Bill of Materials information for an image.
type SBOMInfo struct {
	// Format is the SBOM format (e.g., "spdx-json", "cyclonedx-json", "syft-json").
	// +optional
	Format string `json:"format,omitempty"`

	// GeneratedAt is the timestamp when SBOM was generated.
	// +optional
	GeneratedAt *metav1.Time `json:"generatedAt,omitempty"`

	// TotalPackages is the total number of packages found.
	// +optional
	TotalPackages int `json:"totalPackages,omitempty"`

	// Packages contains the list of packages in the image.
	// Limited to top-level packages for status size optimization.
	// +optional
	Packages []PackageInfo `json:"packages,omitempty"`

	// PackageTypes contains summary by package type.
	// +optional
	PackageTypes map[string]int `json:"packageTypes,omitempty"`

	// Dependencies contains critical dependency information.
	// +optional
	Dependencies *DependencySummary `json:"dependencies,omitempty"`
}

// PackageInfo contains information about a software package in the image.
type PackageInfo struct {
	// Name is the package name.
	Name string `json:"name"`

	// Version is the package version.
	// +optional
	Version string `json:"version,omitempty"`

	// Type is the package type (e.g., "deb", "rpm", "python", "npm", "go", "java").
	// +optional
	Type string `json:"type,omitempty"`

	// VulnerabilityCount is the number of known vulnerabilities in this package.
	// +optional
	VulnerabilityCount int `json:"vulnerabilityCount,omitempty"`

	// Critical indicates if this package has critical vulnerabilities.
	// +optional
	Critical bool `json:"critical,omitempty"`
}

// DependencySummary contains dependency analysis information.
type DependencySummary struct {
	// Direct is the number of direct dependencies.
	// +optional
	Direct int `json:"direct,omitempty"`

	// Transitive is the number of transitive dependencies.
	// +optional
	Transitive int `json:"transitive,omitempty"`

	// Outdated is the number of packages with newer versions available.
	// +optional
	Outdated int `json:"outdated,omitempty"`

	// TopLevelPackages contains the most important packages (base OS, frameworks).
	// +optional
	TopLevelPackages []string `json:"topLevelPackages,omitempty"`
}

// ProvenanceInfo contains provenance information for an image.
type ProvenanceInfo struct {
	// Builder is the builder identity from SLSA provenance.
	// Example: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"
	// +optional
	Builder string `json:"builder,omitempty"`

	// SourceRepo is the source repository URI.
	// +optional
	SourceRepo string `json:"sourceRepo,omitempty"`

	// SourceCommit is the source commit digest (SHA).
	// +optional
	SourceCommit string `json:"sourceCommit,omitempty"`

	// SLSALevel is the derived SLSA provenance level (0-3).
	// +optional
	SLSALevel int `json:"slsaLevel,omitempty"`

	// Signed indicates whether a signature attestation was found.
	// +optional
	Signed bool `json:"signed,omitempty"`

	// LastCheckTime is the timestamp of the last provenance check.
	// +optional
	LastCheckTime *metav1.Time `json:"lastCheckTime,omitempty"`
}

// WebhookConfig defines webhook notification settings.
type WebhookConfig struct {
	// Enabled enables webhook notifications.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// URL is the webhook endpoint URL.
	URL string `json:"url"`

	// Events specifies which events trigger notifications.
	// Supported events: "scan-completed", "vulnerability-critical".
	// If empty, all events are sent.
	// +optional
	Events []string `json:"events,omitempty"`

	// AuthSecret references a Secret containing authentication credentials.
	// Supports keys: "token" (Bearer auth) or "username"+"password" (Basic auth).
	// +optional
	AuthSecret *WebhookAuthSecret `json:"authSecret,omitempty"`

	// InsecureSkipVerify skips TLS certificate verification.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// Timeout is the HTTP request timeout (e.g., "10s", "30s").
	// Defaults to "10s".
	// +optional
	Timeout string `json:"timeout,omitempty"`
}

// WebhookAuthSecret references a Secret containing webhook authentication credentials.
type WebhookAuthSecret struct {
	// Name is the name of the Secret.
	Name string `json:"name"`

	// TokenKey is the key in the Secret containing the Bearer token.
	// If specified, Bearer authentication is used.
	// +optional
	TokenKey string `json:"tokenKey,omitempty"`

	// UsernameKey is the key in the Secret containing the username for Basic auth.
	// Defaults to "username".
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// PasswordKey is the key in the Secret containing the password for Basic auth.
	// Defaults to "password".
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// DriftDetectionConfig defines drift detection settings.
type DriftDetectionConfig struct {
	// Enabled enables drift detection.
	// When enabled, tracks Deployments, StatefulSets, and DaemonSets.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Namespaces is the list of namespaces to monitor. Empty means all namespaces.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// CheckInterval is the interval between drift checks in seconds.
	// Defaults to scanInterval if not specified.
	// +optional
	CheckInterval int64 `json:"checkInterval,omitempty"`
}

// WebhookStatus tracks webhook notification state.
type WebhookStatus struct {
	// LastSentTime is the timestamp of the last successful notification.
	// +optional
	LastSentTime *metav1.Time `json:"lastSentTime,omitempty"`

	// LastStatus is the result of the last notification attempt: "Sent" or "Failed".
	// +optional
	LastStatus string `json:"lastStatus,omitempty"`

	// LastEvent is the event type of the last notification.
	// +optional
	LastEvent string `json:"lastEvent,omitempty"`

	// Message contains details about the last notification attempt.
	// +optional
	Message string `json:"message,omitempty"`
}

// DriftStatus contains drift detection results.
type DriftStatus struct {
	// LastCheckTime is the timestamp of the last drift check.
	// +optional
	LastCheckTime *metav1.Time `json:"lastCheckTime,omitempty"`

	// Workloads contains drift information for each workload.
	// +optional
	Workloads []WorkloadDrift `json:"workloads,omitempty"`

	// Summary contains aggregated drift statistics.
	// +optional
	Summary *DriftSummary `json:"summary,omitempty"`
}

// WorkloadDrift contains drift information for a single workload.
type WorkloadDrift struct {
	// Namespace is the workload namespace.
	Namespace string `json:"namespace"`

	// Name is the workload name.
	Name string `json:"name"`

	// Kind is the workload kind (Deployment, StatefulSet, DaemonSet, etc.).
	Kind string `json:"kind"`

	// CurrentImage is the image currently used by the workload.
	CurrentImage string `json:"currentImage"`

	// CurrentTag is the parsed tag from current image.
	// +optional
	CurrentTag string `json:"currentTag,omitempty"`

	// Status indicates drift status: "LATEST", "OUTDATED", "VULNERABLE", "UNKNOWN".
	Status string `json:"status"`

	// AvailableUpdates contains newer tags available in registry.
	// +optional
	AvailableUpdates []AvailableUpdate `json:"availableUpdates,omitempty"`

	// Recommendation provides update guidance.
	// +optional
	Recommendation string `json:"recommendation,omitempty"`

	// Message provides additional context or warnings.
	// +optional
	Message string `json:"message,omitempty"`
}

// AvailableUpdate contains information about an available image update.
type AvailableUpdate struct {
	// Tag is the available tag.
	Tag string `json:"tag"`

	// Newer indicates if this tag is newer than current.
	// +optional
	Newer bool `json:"newer,omitempty"`

	// CriticalCVEsFixed is the number of critical CVEs fixed in this version.
	// +optional
	CriticalCVEsFixed int `json:"criticalCVEsFixed,omitempty"`

	// HighCVEsFixed is the number of high CVEs fixed in this version.
	// +optional
	HighCVEsFixed int `json:"highCVEsFixed,omitempty"`

	// NewCVEs is the number of new CVEs introduced in this version.
	// +optional
	NewCVEs int `json:"newCVEs,omitempty"`

	// Recommendation provides update guidance for this specific version.
	// +optional
	Recommendation string `json:"recommendation,omitempty"`

	// SizeDiff is the size difference in bytes (negative means smaller).
	// +optional
	SizeDiff int64 `json:"sizeDiff,omitempty"`
}

// DriftSummary contains aggregated drift statistics.
type DriftSummary struct {
	// Total is the total number of workloads tracked.
	Total int `json:"total,omitempty"`

	// Latest is the number of workloads using latest available image.
	Latest int `json:"latest,omitempty"`

	// Outdated is the number of workloads with newer images available.
	Outdated int `json:"outdated,omitempty"`

	// Vulnerable is the number of workloads with critical vulnerabilities.
	Vulnerable int `json:"vulnerable,omitempty"`

	// Unknown is the number of workloads with unknown image status.
	Unknown int `json:"unknown,omitempty"`

	// UrgentUpdates is the number of workloads needing urgent updates.
	UrgentUpdates int `json:"urgentUpdates,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.lastScanStatus`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Registry is the Schema for the registries API.
type Registry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RegistrySpec   `json:"spec,omitempty"`
	Status RegistryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RegistryList contains a list of Registry.
type RegistryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Registry `json:"items"`
}
