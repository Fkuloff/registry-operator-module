// Package testutil provides test fixtures and builders for testing.
package testutil

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// NewFakeClient creates a fake Kubernetes client for testing.
func NewFakeClient(objs ...runtime.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objs...).
		Build()
}

// NewTestRegistry creates a Registry resource for testing.
func NewTestRegistry(name, namespace string) *v1alpha1.Registry {
	return &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.RegistrySpec{
			URL:          "https://registry.example.com",
			Repository:   "library/test",
			ScanInterval: 300,
		},
	}
}

// NewTestRegistryWithConfig creates a Registry resource with custom config for testing.
func NewTestRegistryWithConfig(name, namespace string, scanConfig *v1alpha1.ScanConfig) *v1alpha1.Registry {
	reg := NewTestRegistry(name, namespace)
	reg.Spec.ScanConfig = scanConfig
	return reg
}

// NewTestSecret creates a Secret for testing.
func NewTestSecret(name, namespace, username, password string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"username": []byte(username),
			"password": []byte(password),
		},
	}
}

// NewTestSecretWithKeys creates a Secret with custom key names for testing.
func NewTestSecretWithKeys(name, namespace, usernameKey, passwordKey, username, password string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			usernameKey: []byte(username),
			passwordKey: []byte(password),
		},
	}
}

// NewTestImageInfo creates an ImageInfo for testing.
func NewTestImageInfo(tag string, size int64, critical, high, medium, low int) v1alpha1.ImageInfo {
	return v1alpha1.ImageInfo{
		Tag:    tag,
		Digest: "sha256:abcd1234",
		Size:   size,
		Vulnerabilities: &v1alpha1.VulnerabilitySummary{
			Total:    critical + high + medium + low,
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
		},
	}
}

// NewTestPackageInfo creates a PackageInfo for testing.
func NewTestPackageInfo(name, version, pkgType string, critical bool, vulnCount int) v1alpha1.PackageInfo {
	return v1alpha1.PackageInfo{
		Name:               name,
		Version:            version,
		Type:               pkgType,
		Critical:           critical,
		VulnerabilityCount: vulnCount,
	}
}
