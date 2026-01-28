// Package drift provides drift detection functionality.
package drift

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// Scanner scans Kubernetes workloads to find images in use.
type Scanner struct {
	client client.Client
}

// NewScanner creates a new drift scanner.
func NewScanner(c client.Client) *Scanner {
	return &Scanner{
		client: c,
	}
}

// WorkloadImage represents an image used by a workload.
type WorkloadImage struct {
	Namespace string
	Name      string
	Kind      string
	Image     string
	Tag       string
}

// ImageRef represents a parsed image reference.
type ImageRef struct {
	Image string
	Tag   string
}

// ScanWorkloads scans for workloads using images from the specified repository.
// Scans Deployments, StatefulSets, and DaemonSets only.
func (s *Scanner) ScanWorkloads(
	ctx context.Context,
	repository string,
	config *v1alpha1.DriftDetectionConfig,
) ([]WorkloadImage, error) {
	if config == nil || !config.Enabled {
		return nil, nil
	}

	var workloads []WorkloadImage

	deployments, err := s.scanDeployments(ctx, repository, config.Namespaces)
	if err != nil {
		return nil, fmt.Errorf("scan deployments: %w", err)
	}
	workloads = append(workloads, deployments...)

	statefulSets, err := s.scanStatefulSets(ctx, repository, config.Namespaces)
	if err != nil {
		return nil, fmt.Errorf("scan statefulsets: %w", err)
	}
	workloads = append(workloads, statefulSets...)

	daemonSets, err := s.scanDaemonSets(ctx, repository, config.Namespaces)
	if err != nil {
		return nil, fmt.Errorf("scan daemonsets: %w", err)
	}
	workloads = append(workloads, daemonSets...)

	return workloads, nil
}

// workloadExtractor defines a function that extracts namespace, name, and podspec from a workload.
type workloadExtractor func(obj client.Object) (namespace, name string, podSpec corev1.PodSpec)

// scanWorkloadType scans a specific workload type for matching images.
func (s *Scanner) scanWorkloadType(
	ctx context.Context,
	list client.ObjectList,
	kind string,
	repository string,
	namespaces []string,
	extract workloadExtractor,
) ([]WorkloadImage, error) {
	var workloads []WorkloadImage

	for _, ns := range resolveNamespaces(namespaces) {
		listOpts := &client.ListOptions{Namespace: ns}

		if err := s.client.List(ctx, list, listOpts); err != nil {
			return nil, fmt.Errorf("list %s in %s: %w", kind, ns, err)
		}

		items := extractItems(list)
		for _, item := range items {
			namespace, name, podSpec := extract(item)
			images := extractImages(podSpec, repository)

			for _, img := range images {
				workloads = append(workloads, WorkloadImage{
					Namespace: namespace,
					Name:      name,
					Kind:      kind,
					Image:     img.Image,
					Tag:       img.Tag,
				})
			}
		}
	}

	return workloads, nil
}

// extractItemsTyped converts a slice of any type to []client.Object.
// Uses generics to avoid code duplication for different workload types.
func extractItemsTyped[T any](items []T) []client.Object {
	result := make([]client.Object, len(items))
	for i := range items {
		result[i] = any(&items[i]).(client.Object)
	}
	return result
}

// extractItems extracts client.Object items from client.ObjectList.
func extractItems(list client.ObjectList) []client.Object {
	switch v := list.(type) {
	case *appsv1.DeploymentList:
		return extractItemsTyped(v.Items)
	case *appsv1.StatefulSetList:
		return extractItemsTyped(v.Items)
	case *appsv1.DaemonSetList:
		return extractItemsTyped(v.Items)
	}
	return nil
}

// scanDeployments scans Deployments for matching images.
func (s *Scanner) scanDeployments(
	ctx context.Context,
	repository string,
	namespaces []string,
) ([]WorkloadImage, error) {
	return s.scanWorkloadType(
		ctx,
		&appsv1.DeploymentList{},
		"Deployment",
		repository,
		namespaces,
		func(obj client.Object) (string, string, corev1.PodSpec) {
			d := obj.(*appsv1.Deployment)
			return d.Namespace, d.Name, d.Spec.Template.Spec
		},
	)
}

// scanStatefulSets scans StatefulSets for matching images.
func (s *Scanner) scanStatefulSets(
	ctx context.Context,
	repository string,
	namespaces []string,
) ([]WorkloadImage, error) {
	return s.scanWorkloadType(
		ctx,
		&appsv1.StatefulSetList{},
		"StatefulSet",
		repository,
		namespaces,
		func(obj client.Object) (string, string, corev1.PodSpec) {
			s := obj.(*appsv1.StatefulSet)
			return s.Namespace, s.Name, s.Spec.Template.Spec
		},
	)
}

// scanDaemonSets scans DaemonSets for matching images.
func (s *Scanner) scanDaemonSets(
	ctx context.Context,
	repository string,
	namespaces []string,
) ([]WorkloadImage, error) {
	return s.scanWorkloadType(
		ctx,
		&appsv1.DaemonSetList{},
		"DaemonSet",
		repository,
		namespaces,
		func(obj client.Object) (string, string, corev1.PodSpec) {
			d := obj.(*appsv1.DaemonSet)
			return d.Namespace, d.Name, d.Spec.Template.Spec
		},
	)
}

// extractImages extracts images from pod spec that match the repository.
func extractImages(podSpec corev1.PodSpec, repository string) []ImageRef {
	var images []ImageRef

	for _, container := range podSpec.Containers {
		if img, tag := parseImage(container.Image, repository); img != "" {
			images = append(images, ImageRef{
				Image: img,
				Tag:   tag,
			})
		}
	}

	for _, container := range podSpec.InitContainers {
		if img, tag := parseImage(container.Image, repository); img != "" {
			images = append(images, ImageRef{
				Image: img,
				Tag:   tag,
			})
		}
	}

	return images
}

// parseImage parses an image reference and checks if it matches the repository.
// Returns the full image and tag if it matches, empty strings otherwise.
func parseImage(imageRef, repository string) (string, string) {
	parts := strings.Split(imageRef, ":")
	imagePath := parts[0]
	tag := "latest"

	if len(parts) > 1 {
		tag = parts[1]
	}

	repoPath := normalizeRepository(repository)
	imgPath := normalizeRepository(imagePath)

	if !strings.HasSuffix(imgPath, repoPath) {
		return "", ""
	}

	return imageRef, tag
}

// normalizeRepository normalizes repository paths for comparison.
func normalizeRepository(repo string) string {
	parts := strings.Split(repo, "/")

	// Remove registry prefix if present (e.g., "registry.io/library/nginx")
	if len(parts) > 2 && strings.Contains(parts[0], ".") {
		return strings.Join(parts[1:], "/")
	}

	// Handle Docker Hub shorthand: "nginx" -> "library/nginx"
	if len(parts) == 1 {
		return "library/" + repo
	}

	return repo
}

// resolveNamespaces returns the list of namespaces to scan.
// If namespaces list is empty, returns all namespaces.
func resolveNamespaces(namespaces []string) []string {
	if len(namespaces) > 0 {
		return namespaces
	}
	return []string{""}
}
