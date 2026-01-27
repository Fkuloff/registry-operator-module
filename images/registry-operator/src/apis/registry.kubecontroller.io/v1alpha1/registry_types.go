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

	// Vulnerabilities contains vulnerability scan results.
	// +optional
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`
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
