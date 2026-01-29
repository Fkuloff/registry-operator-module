package drift

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

//nolint:funlen // table-driven test with many cases
func TestIsNewerVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		giveCurrent   string
		giveCandidate string
		want          bool
	}{
		{
			name:          "simple patch increment",
			giveCurrent:   "1.0.0",
			giveCandidate: "1.0.1",
			want:          true,
		},
		{
			name:          "minor version increment",
			giveCurrent:   "1.0.0",
			giveCandidate: "1.1.0",
			want:          true,
		},
		{
			name:          "major version increment",
			giveCurrent:   "1.0.0",
			giveCandidate: "2.0.0",
			want:          true,
		},
		{
			name:          "older version returns false",
			giveCurrent:   "2.0.0",
			giveCandidate: "1.0.0",
			want:          false,
		},
		{
			name:          "same version returns false",
			giveCurrent:   "1.0.0",
			giveCandidate: "1.0.0",
			want:          false,
		},
		{
			name:          "with v prefix both",
			giveCurrent:   "v1.0.0",
			giveCandidate: "v1.1.0",
			want:          true,
		},
		{
			name:          "prerelease to release",
			giveCurrent:   "1.0.0-alpha",
			giveCandidate: "1.0.0",
			want:          true,
		},
		{
			name:          "prerelease alpha to beta",
			giveCurrent:   "1.0.0-alpha",
			giveCandidate: "1.0.0-beta",
			want:          true,
		},
		{
			name:          "release to prerelease returns false",
			giveCurrent:   "1.0.0",
			giveCandidate: "1.0.0-rc.1",
			want:          false,
		},
		{
			name:          "build metadata ignored in comparison",
			giveCurrent:   "1.0.0+build.1",
			giveCandidate: "1.0.0+build.2",
			want:          false,
		},
		{
			name:          "invalid current semver returns false",
			giveCurrent:   "latest",
			giveCandidate: "1.0.0",
			want:          false,
		},
		{
			name:          "invalid candidate semver returns false",
			giveCurrent:   "1.0.0",
			giveCandidate: "dev-branch",
			want:          false,
		},
		{
			name:          "both invalid returns false",
			giveCurrent:   "latest",
			giveCandidate: "dev",
			want:          false,
		},
		{
			name:          "partial version valid",
			giveCurrent:   "1.0",
			giveCandidate: "1.1",
			want:          true,
		},
		{
			name:          "empty current returns false",
			giveCurrent:   "",
			giveCandidate: "1.0.0",
			want:          false,
		},
		{
			name:          "empty candidate returns false",
			giveCurrent:   "1.0.0",
			giveCandidate: "",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isNewerVersion(tt.giveCurrent, tt.giveCandidate)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildImageMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		give  []v1alpha1.ImageInfo
		check func(t *testing.T, got map[string]*v1alpha1.ImageInfo)
	}{
		{
			name: "single image creates single entry",
			give: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0", Digest: "sha256:abc"},
			},
			check: func(t *testing.T, got map[string]*v1alpha1.ImageInfo) {
				assert.Len(t, got, 1)
				assert.Contains(t, got, "v1.0.0")
				assert.Equal(t, "sha256:abc", got["v1.0.0"].Digest)
			},
		},
		{
			name: "multiple images all accessible",
			give: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0", Digest: "sha256:abc"},
				{Tag: "v2.0.0", Digest: "sha256:def"},
				{Tag: "latest", Digest: "sha256:ghi"},
			},
			check: func(t *testing.T, got map[string]*v1alpha1.ImageInfo) {
				assert.Len(t, got, 3)
				assert.Contains(t, got, "v1.0.0")
				assert.Contains(t, got, "v2.0.0")
				assert.Contains(t, got, "latest")
			},
		},
		{
			name: "empty list returns empty map",
			give: []v1alpha1.ImageInfo{},
			check: func(t *testing.T, got map[string]*v1alpha1.ImageInfo) {
				assert.Empty(t, got)
			},
		},
		{
			name: "duplicate tags last wins",
			give: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0", Digest: "sha256:first"},
				{Tag: "v1.0.0", Digest: "sha256:second"},
			},
			check: func(t *testing.T, got map[string]*v1alpha1.ImageInfo) {
				assert.Len(t, got, 1)
				assert.Equal(t, "sha256:second", got["v1.0.0"].Digest)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildImageMap(tt.give)
			tt.check(t, got)
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestSortUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []v1alpha1.AvailableUpdate
		want []string // Expected order of tags
	}{
		{
			name: "urgent update sorts first",
			give: []v1alpha1.AvailableUpdate{
				{Tag: "v3.0.0", Recommendation: RecommendationAvailable},
				{Tag: "v2.0.0", Recommendation: RecommendationUrgentUpdate},
				{Tag: "v1.5.0", Recommendation: RecommendationRecommended},
			},
			want: []string{"v2.0.0", "v1.5.0", "v3.0.0"},
		},
		{
			name: "recommended sorts before available",
			give: []v1alpha1.AvailableUpdate{
				{Tag: "v2.0.0", Recommendation: RecommendationAvailable},
				{Tag: "v1.5.0", Recommendation: RecommendationRecommended},
			},
			want: []string{"v1.5.0", "v2.0.0"},
		},
		{
			name: "caution sorts after available",
			give: []v1alpha1.AvailableUpdate{
				{Tag: "v2.0.0", Recommendation: RecommendationCaution},
				{Tag: "v1.5.0", Recommendation: RecommendationAvailable},
			},
			want: []string{"v1.5.0", "v2.0.0"},
		},
		{
			name: "complete priority order",
			give: []v1alpha1.AvailableUpdate{
				{Tag: "v4.0.0", Recommendation: RecommendationCaution},
				{Tag: "v3.0.0", Recommendation: RecommendationAvailable},
				{Tag: "v2.0.0", Recommendation: RecommendationRecommended},
				{Tag: "v1.0.0", Recommendation: RecommendationUrgentUpdate},
			},
			want: []string{"v1.0.0", "v2.0.0", "v3.0.0", "v4.0.0"},
		},
		{
			name: "same priority maintains order",
			give: []v1alpha1.AvailableUpdate{
				{Tag: "v1.0.0", Recommendation: RecommendationAvailable},
				{Tag: "v2.0.0", Recommendation: RecommendationAvailable},
				{Tag: "v3.0.0", Recommendation: RecommendationAvailable},
			},
			want: []string{"v1.0.0", "v2.0.0", "v3.0.0"},
		},
		{
			name: "empty slice",
			give: []v1alpha1.AvailableUpdate{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Make a copy to avoid modifying test data
			updates := make([]v1alpha1.AvailableUpdate, len(tt.give))
			copy(updates, tt.give)

			sortUpdates(updates)

			got := make([]string, len(updates))
			for i, u := range updates {
				got[i] = u.Tag
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestFindAvailableUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		giveCurrent     string
		giveCurrentInfo *v1alpha1.ImageInfo
		giveAvailable   []v1alpha1.ImageInfo
		wantCount       int
		checkFirst      func(t *testing.T, update v1alpha1.AvailableUpdate)
	}{
		{
			name:        "no updates when only current tag exists",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag:    "v1.0.0",
				Digest: "sha256:abc",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0", Digest: "sha256:abc"},
			},
			wantCount: 0,
		},
		{
			name:        "newer version available",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "v1.0.0",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 0,
					High:     0,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     0,
					},
				},
			},
			wantCount: 1,
			checkFirst: func(t *testing.T, update v1alpha1.AvailableUpdate) {
				assert.Equal(t, "v1.1.0", update.Tag)
				assert.True(t, update.Newer)
				assert.Equal(t, RecommendationAvailable, update.Recommendation)
			},
		},
		{
			name:        "critical cves fixed triggers urgent",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "v1.0.0",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 5,
					High:     3,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 2,
						High:     3,
					},
				},
			},
			wantCount: 1,
			checkFirst: func(t *testing.T, update v1alpha1.AvailableUpdate) {
				assert.Equal(t, "v1.1.0", update.Tag)
				assert.Equal(t, 3, update.CriticalCVEsFixed)
				assert.Equal(t, RecommendationUrgentUpdate, update.Recommendation)
			},
		},
		{
			name:        "high cves fixed triggers recommended",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "v1.0.0",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 0,
					High:     5,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     2,
					},
				},
			},
			wantCount: 1,
			checkFirst: func(t *testing.T, update v1alpha1.AvailableUpdate) {
				assert.Equal(t, "v1.1.0", update.Tag)
				assert.Equal(t, 3, update.HighCVEsFixed)
				assert.Equal(t, RecommendationRecommended, update.Recommendation)
			},
		},
		{
			name:        "new cves introduced triggers caution",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "v1.0.0",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 0,
					High:     0,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 2,
						High:     1,
					},
				},
			},
			wantCount: 1,
			checkFirst: func(t *testing.T, update v1alpha1.AvailableUpdate) {
				assert.Equal(t, "v1.1.0", update.Tag)
				assert.Equal(t, 2, update.NewCVEs) // Only counts CRITICAL
				assert.Equal(t, RecommendationCaution, update.Recommendation)
			},
		},
		{
			name:        "non-semver tags with security improvement included",
			giveCurrent: "latest",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "latest",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 3,
					High:     0,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "latest"},
				{
					Tag: "stable",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 1,
						High:     0,
					},
				},
			},
			wantCount: 1,
			checkFirst: func(t *testing.T, update v1alpha1.AvailableUpdate) {
				assert.Equal(t, "stable", update.Tag)
				assert.False(t, update.Newer) // Non-semver
				assert.Equal(t, 2, update.CriticalCVEsFixed)
				assert.Equal(t, RecommendationUrgentUpdate, update.Recommendation)
			},
		},
		{
			name:        "limits to max 5 updates",
			giveCurrent: "v1.0.0",
			giveCurrentInfo: &v1alpha1.ImageInfo{
				Tag: "v1.0.0",
				Vulnerabilities: &v1alpha1.VulnerabilitySummary{
					Critical: 5,
				},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
				{Tag: "v1.1.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 3}},
				{Tag: "v1.2.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 2}},
				{Tag: "v1.3.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 1}},
				{Tag: "v1.4.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
				{Tag: "v1.5.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
				{Tag: "v1.6.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
				{Tag: "v1.7.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
			},
			wantCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := findAvailableUpdates(tt.giveCurrent, tt.giveCurrentInfo, tt.giveAvailable)

			require.Len(t, got, tt.wantCount)

			if tt.checkFirst != nil && tt.wantCount > 0 {
				tt.checkFirst(t, got[0])
			}
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestAnalyzeWorkload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		giveWorkload       WorkloadImage
		giveAvailable      []v1alpha1.ImageInfo
		wantStatus         string
		wantRecommendation string
		checkMessage       func(t *testing.T, msg string)
	}{
		{
			name: "unknown tag not in registry",
			giveWorkload: WorkloadImage{
				Namespace: "default",
				Name:      "app-deployment",
				Kind:      "Deployment",
				Image:     "registry.example.com/app",
				Tag:       "unknown-tag",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0"},
			},
			wantStatus:         StatusUnknown,
			wantRecommendation: RecommendationReviewRequired,
			checkMessage: func(t *testing.T, msg string) {
				assert.Contains(t, msg, "not found")
			},
		},
		{
			name: "latest version with no vulnerabilities",
			giveWorkload: WorkloadImage{
				Tag: "v1.0.0",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{
					Tag: "v1.0.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     0,
					},
				},
			},
			wantStatus:         StatusLatest,
			wantRecommendation: RecommendationNoAction,
		},
		{
			name: "critical vulnerabilities with no updates",
			giveWorkload: WorkloadImage{
				Tag: "v1.0.0",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{
					Tag: "v1.0.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 3,
						High:     2,
					},
				},
			},
			wantStatus:         StatusVulnerable,
			wantRecommendation: RecommendationUrgentUpdate,
			checkMessage: func(t *testing.T, msg string) {
				assert.Contains(t, msg, "Critical")
			},
		},
		{
			name: "outdated with security fixes available",
			giveWorkload: WorkloadImage{
				Tag: "v1.0.0",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{
					Tag: "v1.0.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 2,
						High:     5,
					},
				},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     2,
					},
				},
			},
			wantStatus:         StatusVulnerable,
			wantRecommendation: RecommendationUrgentUpdate,
		},
		{
			name: "outdated no critical vulns but newer available",
			giveWorkload: WorkloadImage{
				Tag: "v1.0.0",
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{
					Tag: "v1.0.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     0,
					},
				},
				{
					Tag: "v1.1.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{
						Critical: 0,
						High:     0,
					},
				},
			},
			wantStatus:         StatusOutdated,
			wantRecommendation: RecommendationUpdateAvailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imageMap := buildImageMap(tt.giveAvailable)
			got := analyzeWorkload(tt.giveWorkload, imageMap, tt.giveAvailable)

			assert.Equal(t, tt.wantStatus, got.Status)
			assert.Equal(t, tt.wantRecommendation, got.Recommendation)

			if tt.checkMessage != nil {
				tt.checkMessage(t, got.Message)
			}
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestAnalyzeDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		giveWorkloads []WorkloadImage
		giveAvailable []v1alpha1.ImageInfo
		checkSummary  func(t *testing.T, summary *v1alpha1.DriftSummary)
	}{
		{
			name:          "empty workloads returns empty status",
			giveWorkloads: []WorkloadImage{},
			giveAvailable: []v1alpha1.ImageInfo{{Tag: "v1.0.0"}},
			checkSummary: func(t *testing.T, summary *v1alpha1.DriftSummary) {
				assert.Equal(t, 0, summary.Total)
				assert.Equal(t, 0, summary.Latest)
				assert.Equal(t, 0, summary.Outdated)
				assert.Equal(t, 0, summary.Vulnerable)
				assert.Equal(t, 0, summary.Unknown)
			},
		},
		{
			name: "single workload latest status",
			giveWorkloads: []WorkloadImage{
				{Namespace: "default", Name: "app", Kind: "Deployment", Tag: "v1.0.0"},
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{
					Tag:             "v1.0.0",
					Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0},
				},
			},
			checkSummary: func(t *testing.T, summary *v1alpha1.DriftSummary) {
				assert.Equal(t, 1, summary.Total)
				assert.Equal(t, 1, summary.Latest)
				assert.Equal(t, 0, summary.Outdated)
				assert.Equal(t, 0, summary.Vulnerable)
				assert.Equal(t, 0, summary.UrgentUpdates)
			},
		},
		{
			name: "multiple statuses counted correctly",
			giveWorkloads: []WorkloadImage{
				{Tag: "v1.0.0"},  // Latest
				{Tag: "v0.9.0"},  // Outdated
				{Tag: "v0.8.0"},  // Vulnerable
				{Tag: "unknown"}, // Unknown
			},
			giveAvailable: []v1alpha1.ImageInfo{
				{Tag: "v1.0.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
				{Tag: "v0.9.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 0}},
				{Tag: "v0.8.0", Vulnerabilities: &v1alpha1.VulnerabilitySummary{Critical: 3}},
			},
			checkSummary: func(t *testing.T, summary *v1alpha1.DriftSummary) {
				assert.Equal(t, 4, summary.Total)
				assert.Equal(t, 1, summary.Latest)
				assert.Equal(t, 1, summary.Outdated)
				assert.Equal(t, 1, summary.Vulnerable)
				assert.Equal(t, 1, summary.Unknown)
				assert.Equal(t, 1, summary.UrgentUpdates)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := AnalyzeDrift(tt.giveWorkloads, tt.giveAvailable)

			require.NotNil(t, got)
			require.NotNil(t, got.Summary)
			require.NotNil(t, got.LastCheckTime)

			tt.checkSummary(t, got.Summary)
		})
	}
}
