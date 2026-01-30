package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

func TestFilterTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    []string
		filter  *v1alpha1.TagFilter
		want    []string
		wantErr bool
	}{
		{
			name:   "no filter returns all tags",
			give:   []string{"v1.0", "v2.0", "latest"},
			filter: nil,
			want:   []string{"v1.0", "v2.0", "latest"},
		},
		{
			name: "include pattern matches semantic versions",
			give: []string{"v1.0.0", "v1.1.0", "v2.0.0", "dev-latest", "staging"},
			filter: &v1alpha1.TagFilter{
				Include: `^v\d+\.\d+\.\d+$`,
			},
			want: []string{"v1.0.0", "v1.1.0", "v2.0.0"},
		},
		{
			name: "exclude pattern filters development tags",
			give: []string{"v1.0", "v2.0", "dev", "staging", "prod"},
			filter: &v1alpha1.TagFilter{
				Exclude: `^(dev|staging)$`,
			},
			want: []string{"prod", "v1.0", "v2.0"},
		},
		{
			name: "limit reduces result count",
			give: []string{"a", "b", "c", "d", "e"},
			filter: &v1alpha1.TagFilter{
				Limit: 2,
			},
			want: []string{"a", "b"},
		},
		{
			name: "sort by newest reverses alphabetical order",
			give: []string{"v1.0", "v2.0", "v3.0"},
			filter: &v1alpha1.TagFilter{
				SortBy: "newest",
			},
			want: []string{"v3.0", "v2.0", "v1.0"},
		},
		{
			name: "sort by oldest maintains alphabetical order",
			give: []string{"v3.0", "v1.0", "v2.0"},
			filter: &v1alpha1.TagFilter{
				SortBy: "oldest",
			},
			want: []string{"v1.0", "v2.0", "v3.0"},
		},
		{
			name: "empty sort defaults to alphabetical",
			give: []string{"c", "a", "b"},
			filter: &v1alpha1.TagFilter{
				SortBy: "",
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "invalid include regex returns error",
			give: []string{"v1.0"},
			filter: &v1alpha1.TagFilter{
				Include: "[invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid exclude regex returns error",
			give: []string{"v1.0"},
			filter: &v1alpha1.TagFilter{
				Exclude: "(unclosed",
			},
			wantErr: true,
		},
		{
			name: "combined include exclude and limit",
			give: []string{"v1.0", "v1.1", "v2.0", "v2.1", "dev-v1.0", "staging-v2.0"},
			filter: &v1alpha1.TagFilter{
				Include: `^v\d+\.\d+$`,
				Exclude: `v1\.`,
				Limit:   1,
			},
			want: []string{"v2.0"},
		},
		{
			name: "include pattern with no matches returns empty",
			give: []string{"latest", "dev", "staging"},
			filter: &v1alpha1.TagFilter{
				Include: `^v\d+\.\d+\.\d+$`,
			},
			want: []string{},
		},
		{
			name: "limit larger than result count returns all",
			give: []string{"a", "b"},
			filter: &v1alpha1.TagFilter{
				Limit: 10,
			},
			want: []string{"a", "b"},
		},
		{
			name: "limit zero returns all",
			give: []string{"a", "b", "c"},
			filter: &v1alpha1.TagFilter{
				Limit: 0,
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty tag list returns empty",
			give: []string{},
			filter: &v1alpha1.TagFilter{
				Include: ".*",
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := filterTags(tt.give, tt.filter)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetScanConfig(t *testing.T) {
	t.Parallel()

	r := &RegistryReconciler{}

	// Default config for comparison
	defaultCfg := resolvedScanConfig{
		timeout:       30 * time.Second,
		retryAttempts: 3,
		retryDelay:    5 * time.Second,
		concurrency:   1,
	}

	tests := []struct {
		name string
		give *v1alpha1.Registry
		want resolvedScanConfig
	}{
		{
			name: "nil scan config uses all defaults",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: nil,
				},
			},
			want: defaultCfg,
		},
		{
			name: "empty scan config uses all defaults",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{},
				},
			},
			want: defaultCfg,
		},
		{
			name: "custom timeout overrides default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						Timeout: "1m",
					},
				},
			},
			want: resolvedScanConfig{
				timeout:       1 * time.Minute,
				retryAttempts: defaultCfg.retryAttempts,
				retryDelay:    defaultCfg.retryDelay,
				concurrency:   defaultCfg.concurrency,
			},
		},
		{
			name: "custom retry attempts overrides default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						RetryAttempts: 5,
					},
				},
			},
			want: resolvedScanConfig{
				timeout:       defaultCfg.timeout,
				retryAttempts: 5,
				retryDelay:    defaultCfg.retryDelay,
				concurrency:   defaultCfg.concurrency,
			},
		},
		{
			name: "custom retry delay overrides default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						RetryDelay: "10s",
					},
				},
			},
			want: resolvedScanConfig{
				timeout:       defaultCfg.timeout,
				retryAttempts: defaultCfg.retryAttempts,
				retryDelay:    10 * time.Second,
				concurrency:   defaultCfg.concurrency,
			},
		},
		{
			name: "custom concurrency overrides default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						Concurrency: 4,
					},
				},
			},
			want: resolvedScanConfig{
				timeout:       defaultCfg.timeout,
				retryAttempts: defaultCfg.retryAttempts,
				retryDelay:    defaultCfg.retryDelay,
				concurrency:   4,
			},
		},
		{
			name: "all custom values override defaults",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						Timeout:       "2m",
						RetryAttempts: 5,
						RetryDelay:    "10s",
						Concurrency:   4,
					},
				},
			},
			want: resolvedScanConfig{
				timeout:       2 * time.Minute,
				retryAttempts: 5,
				retryDelay:    10 * time.Second,
				concurrency:   4,
			},
		},
		{
			name: "invalid timeout falls back to default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						Timeout: "invalid",
					},
				},
			},
			want: defaultCfg,
		},
		{
			name: "invalid retry delay falls back to default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						RetryDelay: "not-a-duration",
					},
				},
			},
			want: defaultCfg,
		},
		{
			name: "zero retry attempts uses default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						RetryAttempts: 0,
					},
				},
			},
			want: defaultCfg,
		},
		{
			name: "zero concurrency uses default",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					ScanConfig: &v1alpha1.ScanConfig{
						Concurrency: 0,
					},
				},
			},
			want: defaultCfg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := r.getScanConfig(tt.give)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildImageRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		giveURL  string
		giveRepo string
		giveTag  string
		want     string
	}{
		{
			name:     "https registry url",
			giveURL:  "https://registry.example.com",
			giveRepo: "myrepo",
			giveTag:  "v1.0.0",
			want:     "registry.example.com/myrepo:v1.0.0",
		},
		{
			name:     "http registry url",
			giveURL:  "http://registry.example.com",
			giveRepo: "myrepo",
			giveTag:  "latest",
			want:     "registry.example.com/myrepo:latest",
		},
		{
			name:     "no scheme in url",
			giveURL:  "registry.example.com",
			giveRepo: "myrepo",
			giveTag:  "v2.0.0",
			want:     "registry.example.com/myrepo:v2.0.0",
		},
		{
			name:     "localhost with port",
			giveURL:  "https://localhost:5000",
			giveRepo: "test-image",
			giveTag:  "dev",
			want:     "localhost:5000/test-image:dev",
		},
		{
			name:     "repository with path",
			giveURL:  "https://registry.example.com",
			giveRepo: "library/nginx",
			giveTag:  "1.21-alpine",
			want:     "registry.example.com/library/nginx:1.21-alpine",
		},
		{
			name:     "docker hub",
			giveURL:  "https://index.docker.io",
			giveRepo: "library/ubuntu",
			giveTag:  "22.04",
			want:     "index.docker.io/library/ubuntu:22.04",
		},
		{
			name:     "tag with special characters",
			giveURL:  "https://registry.example.com",
			giveRepo: "myrepo",
			giveTag:  "v1.0.0-rc.1+build.123",
			want:     "registry.example.com/myrepo:v1.0.0-rc.1+build.123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildImageRef(tt.giveURL, tt.giveRepo, tt.giveTag)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShouldScanVulnerabilities(t *testing.T) {
	t.Parallel()

	r := &RegistryReconciler{}

	now := metav1.Now()
	thirtyMinutesAgo := metav1.NewTime(now.Add(-30 * time.Minute))
	twoHoursAgo := metav1.NewTime(now.Add(-2 * time.Hour))

	tests := []struct {
		name string
		give *v1alpha1.Registry
		want bool
	}{
		{
			name: "disabled returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: &v1alpha1.VulnerabilityScanConfig{
						Enabled: false,
					},
				},
			},
			want: false,
		},
		{
			name: "nil config returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: nil,
				},
			},
			want: false,
		},
		{
			name: "enabled with no previous scan returns true",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: &v1alpha1.VulnerabilityScanConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{Tag: "v1.0.0"},
					},
				},
			},
			want: true,
		},
		{
			name: "recent scan within interval returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: &v1alpha1.VulnerabilityScanConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{
							Tag: "v1.0.0",
							Vulnerabilities: &v1alpha1.VulnerabilitySummary{
								LastScanTime: &thirtyMinutesAgo,
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "old scan beyond interval returns true",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: &v1alpha1.VulnerabilityScanConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{
							Tag: "v1.0.0",
							Vulnerabilities: &v1alpha1.VulnerabilitySummary{
								LastScanTime: &twoHoursAgo,
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "default interval with no previous scan returns true",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					VulnerabilityScanning: &v1alpha1.VulnerabilityScanConfig{
						Enabled:      true,
						ScanInterval: 0,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{Tag: "v1.0.0"},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := r.shouldScanVulnerabilities(tt.give)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShouldScanSBOM(t *testing.T) {
	t.Parallel()

	r := &RegistryReconciler{}

	now := metav1.Now()
	thirtyMinutesAgo := metav1.NewTime(now.Add(-30 * time.Minute))
	twoHoursAgo := metav1.NewTime(now.Add(-2 * time.Hour))

	tests := []struct {
		name string
		give *v1alpha1.Registry
		want bool
	}{
		{
			name: "disabled returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					SBOMGeneration: &v1alpha1.SBOMConfig{
						Enabled: false,
					},
				},
			},
			want: false,
		},
		{
			name: "nil config returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					SBOMGeneration: nil,
				},
			},
			want: false,
		},
		{
			name: "enabled with no previous scan returns true",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					SBOMGeneration: &v1alpha1.SBOMConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{Tag: "v1.0.0"},
					},
				},
			},
			want: true,
		},
		{
			name: "recent scan within interval returns false",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					SBOMGeneration: &v1alpha1.SBOMConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{
							Tag: "v1.0.0",
							SBOM: &v1alpha1.SBOMInfo{
								GeneratedAt: &thirtyMinutesAgo,
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "old scan beyond interval returns true",
			give: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					SBOMGeneration: &v1alpha1.SBOMConfig{
						Enabled:      true,
						ScanInterval: 3600,
					},
				},
				Status: v1alpha1.RegistryStatus{
					Images: []v1alpha1.ImageInfo{
						{
							Tag: "v1.0.0",
							SBOM: &v1alpha1.SBOMInfo{
								GeneratedAt: &twoHoursAgo,
							},
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := r.shouldScanSBOM(tt.give)
			assert.Equal(t, tt.want, got)
		})
	}
}
