package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

func TestIsDirectDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		givePkg string
		want    bool
	}{
		{
			name:    "base image identified",
			givePkg: "alpine-base",
			want:    true,
		},
		{
			name:    "python runtime identified",
			givePkg: "python3",
			want:    true,
		},
		{
			name:    "node runtime identified",
			givePkg: "nodejs-runtime",
			want:    true,
		},
		{
			name:    "jdk identified",
			givePkg: "openjdk-11-jdk",
			want:    true,
		},
		{
			name:    "glibc identified",
			givePkg: "glibc",
			want:    true,
		},
		{
			name:    "busybox identified",
			givePkg: "busybox-static",
			want:    true,
		},
		{
			name:    "application package not direct",
			givePkg: "my-app-backend",
			want:    false,
		},
		{
			name:    "random library not direct",
			givePkg: "libsomething",
			want:    false,
		},
		{
			name:    "case insensitive matching",
			givePkg: "PYTHON3-DEV",
			want:    true,
		},
		{
			name:    "empty package name",
			givePkg: "",
			want:    false,
		},
		{
			name:    "gcc compiler identified",
			givePkg: "gcc-multilib",
			want:    true,
		},
		{
			name:    "musl libc identified",
			givePkg: "musl-dev",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isDirectDependency(tt.givePkg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCalculatePackageImportance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		givePkg v1alpha1.PackageInfo
		wantMin int
	}{
		{
			name: "critical openssl with vulnerabilities",
			givePkg: v1alpha1.PackageInfo{
				Name:               "openssl",
				Type:               "deb",
				Critical:           true,
				VulnerabilityCount: 5,
			},
			wantMin: 36, // 9 (openssl) + 2 (deb) + 20 (critical) + 5 (vulns) = 36
		},
		{
			name: "basic library no issues",
			givePkg: v1alpha1.PackageInfo{
				Name: "some-random-lib",
				Type: "unknown",
			},
			wantMin: 0,
		},
		{
			name: "python base with multiple keywords",
			givePkg: v1alpha1.PackageInfo{
				Name: "python-base",
				Type: "deb",
			},
			wantMin: 22, // 10 (python) + 10 (base) + 2 (deb) = 22
		},
		{
			name: "system package type bonus",
			givePkg: v1alpha1.PackageInfo{
				Name: "util-linux",
				Type: "deb",
			},
			wantMin: 2, // Only system package type bonus
		},
		{
			name: "non-system package type no bonus",
			givePkg: v1alpha1.PackageInfo{
				Name: "express",
				Type: "npm",
			},
			wantMin: 0,
		},
		{
			name: "critical flag adds 20 points",
			givePkg: v1alpha1.PackageInfo{
				Name:     "test-package",
				Critical: true,
			},
			wantMin: 20,
		},
		{
			name: "vulnerability count adds to score",
			givePkg: v1alpha1.PackageInfo{
				Name:               "test-package",
				VulnerabilityCount: 10,
			},
			wantMin: 10,
		},
		{
			name: "kernel package high importance",
			givePkg: v1alpha1.PackageInfo{
				Name: "linux-kernel",
				Type: "rpm",
			},
			wantMin: 11, // 9 (kernel) + 2 (rpm) = 11
		},
		{
			name: "database package identified",
			givePkg: v1alpha1.PackageInfo{
				Name: "postgresql-client",
				Type: "deb",
			},
			wantMin: 10, // 8 (postgresql) + 2 (deb) = 10
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := calculatePackageImportance(tt.givePkg)
			assert.GreaterOrEqual(t, got, tt.wantMin)
		})
	}
}

func TestIdentifyTopLevelPackages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		givePkgs  []v1alpha1.PackageInfo
		giveLimit int
		wantCount int
		checkFunc func(t *testing.T, result []string)
	}{
		{
			name: "returns top packages by score",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "openssl", Type: "deb", Critical: true},      // High score
				{Name: "python3", Type: "deb"},                      // Medium score
				{Name: "random-lib", Type: "unknown"},               // Low score
				{Name: "nodejs", Type: "deb"},                       // Medium score
				{Name: "glibc", Type: "deb", VulnerabilityCount: 5}, // High score
			},
			giveLimit: 3,
			wantCount: 3,
			checkFunc: func(t *testing.T, result []string) {
				// openssl and glibc should be in top due to critical/vulns
				assert.Contains(t, result, "openssl")
				assert.Contains(t, result, "glibc")
			},
		},
		{
			name: "limit larger than available returns all",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "pkg1"},
				{Name: "pkg2"},
			},
			giveLimit: 10,
			wantCount: 2,
		},
		{
			name:      "empty packages returns empty",
			givePkgs:  []v1alpha1.PackageInfo{},
			giveLimit: 10,
			wantCount: 0,
		},
		{
			name: "zero limit returns empty",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "pkg1"},
			},
			giveLimit: 0,
			wantCount: 0,
		},
		{
			name: "sorts by importance score",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "low-importance", Type: "unknown"},
				{Name: "high-importance", Type: "deb", Critical: true},
				{Name: "medium-importance", Type: "deb"},
			},
			giveLimit: 1,
			wantCount: 1,
			checkFunc: func(t *testing.T, result []string) {
				assert.Equal(t, "high-importance", result[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := identifyTopLevelPackages(tt.givePkgs, tt.giveLimit)

			assert.Len(t, got, tt.wantCount)

			if tt.checkFunc != nil {
				tt.checkFunc(t, got)
			}
		})
	}
}

func TestCountDirectDependencies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		givePkgs []v1alpha1.PackageInfo
		want     int
	}{
		{
			name: "all direct dependencies",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "python3"},
				{Name: "nodejs"},
				{Name: "glibc"},
			},
			want: 3,
		},
		{
			name: "no direct dependencies",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "my-app"},
				{Name: "custom-lib"},
			},
			want: 0,
		},
		{
			name: "mixed dependencies",
			givePkgs: []v1alpha1.PackageInfo{
				{Name: "python3"},    // Direct
				{Name: "my-app"},     // Transitive
				{Name: "glibc"},      // Direct
				{Name: "random-lib"}, // Transitive
			},
			want: 2,
		},
		{
			name:     "empty list",
			givePkgs: []v1alpha1.PackageInfo{},
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := countDirectDependencies(tt.givePkgs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnalyzeDependencies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		giveSBOM  *v1alpha1.SBOMInfo
		checkFunc func(t *testing.T, sbom *v1alpha1.SBOMInfo)
	}{
		{
			name:     "nil sbom returns safely",
			giveSBOM: nil,
			checkFunc: func(_ *testing.T, _ *v1alpha1.SBOMInfo) {
				// Should not panic
			},
		},
		{
			name: "empty packages returns safely",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{},
			},
			checkFunc: func(_ *testing.T, _ *v1alpha1.SBOMInfo) {
				// Dependencies should not be set for empty packages
			},
		},
		{
			name: "analyzes all direct and transitive",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "python3"},    // Direct
					{Name: "my-app"},     // Transitive
					{Name: "glibc"},      // Direct
					{Name: "random-lib"}, // Transitive
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				require.NotNil(t, sbom.Dependencies)
				assert.Equal(t, 2, sbom.Dependencies.Direct)
				assert.Equal(t, 2, sbom.Dependencies.Transitive)
				assert.NotEmpty(t, sbom.Dependencies.TopLevelPackages)
			},
		},
		{
			name: "identifies top level packages",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "openssl", Type: "deb", Critical: true},
					{Name: "python3", Type: "deb"},
					{Name: "random-lib", Type: "unknown"},
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				require.NotNil(t, sbom.Dependencies)
				assert.NotEmpty(t, sbom.Dependencies.TopLevelPackages)
				assert.Contains(t, sbom.Dependencies.TopLevelPackages, "openssl")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			analyzer := NewAnalyzer()
			analyzer.AnalyzeDependencies(tt.giveSBOM)

			tt.checkFunc(t, tt.giveSBOM)
		})
	}
}

func TestEnrichWithVulnerabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		giveSBOM  *v1alpha1.SBOMInfo
		giveVulns *v1alpha1.VulnerabilitySummary
		checkFunc func(t *testing.T, sbom *v1alpha1.SBOMInfo)
	}{
		{
			name:      "nil sbom returns safely",
			giveSBOM:  nil,
			giveVulns: &v1alpha1.VulnerabilitySummary{},
			checkFunc: func(_ *testing.T, _ *v1alpha1.SBOMInfo) {
				// Should not panic
			},
		},
		{
			name:      "nil vulnerabilities returns safely",
			giveSBOM:  &v1alpha1.SBOMInfo{Packages: []v1alpha1.PackageInfo{{Name: "pkg"}}},
			giveVulns: nil,
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				// Packages should remain unchanged
				assert.Equal(t, 0, sbom.Packages[0].VulnerabilityCount)
			},
		},
		{
			name: "empty CVEs returns safely",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "openssl"},
				},
			},
			giveVulns: &v1alpha1.VulnerabilitySummary{
				TopCVEs: []v1alpha1.CVEInfo{},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				assert.Equal(t, 0, sbom.Packages[0].VulnerabilityCount)
			},
		},
		{
			name: "matches CVEs to packages",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "openssl"},
					{Name: "curl"},
					{Name: "safe-package"},
				},
			},
			giveVulns: &v1alpha1.VulnerabilitySummary{
				TopCVEs: []v1alpha1.CVEInfo{
					{ID: "CVE-2024-1234", Severity: "CRITICAL", Package: "openssl"},
					{ID: "CVE-2024-5678", Severity: "CRITICAL", Package: "openssl"},
					{ID: "CVE-2024-9999", Severity: "HIGH", Package: "curl"},
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				// Check openssl
				assert.Equal(t, 2, sbom.Packages[0].VulnerabilityCount)
				assert.True(t, sbom.Packages[0].Critical)

				// Check curl
				assert.Equal(t, 1, sbom.Packages[1].VulnerabilityCount)
				assert.False(t, sbom.Packages[1].Critical) // Only HIGH, not CRITICAL

				// Check safe-package
				assert.Equal(t, 0, sbom.Packages[2].VulnerabilityCount)
				assert.False(t, sbom.Packages[2].Critical)
			},
		},
		{
			name: "sets critical flag only for CRITICAL severity",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "pkg-with-critical"},
					{Name: "pkg-with-high"},
				},
			},
			giveVulns: &v1alpha1.VulnerabilitySummary{
				TopCVEs: []v1alpha1.CVEInfo{
					{ID: "CVE-1", Severity: "CRITICAL", Package: "pkg-with-critical"},
					{ID: "CVE-2", Severity: "HIGH", Package: "pkg-with-high"},
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				assert.True(t, sbom.Packages[0].Critical)
				assert.False(t, sbom.Packages[1].Critical)
			},
		},
		{
			name: "cve for non-existent package ignored",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "existing-package"},
				},
			},
			giveVulns: &v1alpha1.VulnerabilitySummary{
				TopCVEs: []v1alpha1.CVEInfo{
					{ID: "CVE-1", Severity: "CRITICAL", Package: "non-existent-package"},
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				// Existing package should remain unchanged
				assert.Equal(t, 0, sbom.Packages[0].VulnerabilityCount)
				assert.False(t, sbom.Packages[0].Critical)
			},
		},
		{
			name: "multiple CVEs same package counted correctly",
			giveSBOM: &v1alpha1.SBOMInfo{
				Packages: []v1alpha1.PackageInfo{
					{Name: "vulnerable-pkg"},
				},
			},
			giveVulns: &v1alpha1.VulnerabilitySummary{
				TopCVEs: []v1alpha1.CVEInfo{
					{ID: "CVE-1", Severity: "CRITICAL", Package: "vulnerable-pkg"},
					{ID: "CVE-2", Severity: "HIGH", Package: "vulnerable-pkg"},
					{ID: "CVE-3", Severity: "MEDIUM", Package: "vulnerable-pkg"},
				},
			},
			checkFunc: func(t *testing.T, sbom *v1alpha1.SBOMInfo) {
				assert.Equal(t, 3, sbom.Packages[0].VulnerabilityCount)
				assert.True(t, sbom.Packages[0].Critical) // Has CRITICAL
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			analyzer := NewAnalyzer()
			analyzer.EnrichWithVulnerabilities(tt.giveSBOM, tt.giveVulns)

			tt.checkFunc(t, tt.giveSBOM)
		})
	}
}
