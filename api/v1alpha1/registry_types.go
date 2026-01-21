package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RegistrySpec struct {
	URL                string           `json:"url"`
	Repository         string           `json:"repository"`
	ScanInterval       int64            `json:"scanInterval,omitempty"`       // +optional
	CredentialsSecret  *SecretReference `json:"credentialsSecret,omitempty"`  // +optional
	InsecureSkipVerify bool             `json:"insecureSkipVerify,omitempty"` // +optional
}

type SecretReference struct {
	Name        string `json:"name"`
	UsernameKey string `json:"usernameKey,omitempty"` // +optional, default: "username"
	PasswordKey string `json:"passwordKey,omitempty"` // +optional, default: "password"
}

type RegistryStatus struct {
	LastScanTime   *metav1.Time `json:"lastScanTime,omitempty"`   // +optional
	LastScanStatus string       `json:"lastScanStatus,omitempty"` // +optional
	Message        string       `json:"message,omitempty"`        // +optional
	Images         []ImageInfo  `json:"images,omitempty"`         // +optional
}

type ImageInfo struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest,omitempty"` // +optional
	Size   int64  `json:"size,omitempty"`   // +optional
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.lastScanStatus`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

type Registry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RegistrySpec   `json:"spec,omitempty"`
	Status RegistryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type RegistryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Registry `json:"items"`
}
