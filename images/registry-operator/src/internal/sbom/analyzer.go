// Package sbom provides SBOM analysis functionality.
package sbom

import (
	"sort"
	"strings"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

var (
	// _directIndicators contains keywords for identifying direct dependencies.
	_directIndicators = []string{
		"base", "runtime", "jre", "jdk", "python", "node",
		"gcc", "glibc", "musl", "busybox", "coreutils",
	}

	// _systemPackageTypes contains package types that are system-level.
	_systemPackageTypes = map[string]bool{
		"deb": true,
		"rpm": true,
		"apk": true,
	}
)

// Analyzer provides dependency analysis capabilities.
type Analyzer struct{}

// NewAnalyzer creates a new SBOM analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// AnalyzeDependencies analyzes dependencies and generates summary.
func (a *Analyzer) AnalyzeDependencies(sbom *v1alpha1.SBOMInfo) {
	if sbom == nil || len(sbom.Packages) == 0 {
		return
	}

	directCount := countDirectDependencies(sbom.Packages)
	sbom.Dependencies = &v1alpha1.DependencySummary{
		Direct:           directCount,
		Transitive:       len(sbom.Packages) - directCount,
		TopLevelPackages: identifyTopLevelPackages(sbom.Packages, 10),
	}
}

// countDirectDependencies counts packages that are likely direct dependencies.
func countDirectDependencies(packages []v1alpha1.PackageInfo) int {
	count := 0
	for _, pkg := range packages {
		if isDirectDependency(pkg.Name) {
			count++
		}
	}
	return count
}

func isDirectDependency(name string) bool {
	nameLower := strings.ToLower(name)
	for _, indicator := range _directIndicators {
		if strings.Contains(nameLower, indicator) {
			return true
		}
	}
	return false
}

// identifyTopLevelPackages identifies the most important packages in the image.
func identifyTopLevelPackages(packages []v1alpha1.PackageInfo, limit int) []string {
	type scoredPkg struct {
		name  string
		score int
	}

	scored := make([]scoredPkg, len(packages))
	for i, pkg := range packages {
		scored[i] = scoredPkg{
			name:  pkg.Name,
			score: calculatePackageImportance(pkg),
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	if limit > len(scored) {
		limit = len(scored)
	}

	result := make([]string, limit)
	for i := 0; i < limit; i++ {
		result[i] = scored[i].name
	}
	return result
}

// _importanceKeywords contains keywords that indicate important packages.
var _importanceKeywords = map[string]int{
	// OS and base
	"base":      10,
	"alpine":    10,
	"debian":    10,
	"ubuntu":    10,
	"centos":    10,
	"rhel":      10,
	"glibc":     9,
	"musl":      9,
	"busybox":   8,
	"coreutils": 8,

	// Runtimes
	"python": 10,
	"java":   10,
	"jdk":    10,
	"jre":    10,
	"node":   10,
	"nodejs": 10,
	"ruby":   10,
	"php":    10,
	"dotnet": 10,
	"go":     10,
	"rust":   10,

	// Security critical
	"openssl":  9,
	"crypto":   8,
	"ssl":      8,
	"tls":      8,
	"security": 7,

	// Web servers & proxies
	"nginx":   8,
	"apache":  8,
	"httpd":   8,
	"tomcat":  8,
	"haproxy": 7,
	"envoy":   7,

	// Databases
	"postgresql": 8,
	"mysql":      8,
	"mariadb":    8,
	"mongodb":    8,
	"redis":      8,

	// Common libraries
	"curl":    7,
	"wget":    7,
	"git":     7,
	"gcc":     7,
	"make":    6,
	"cmake":   6,
	"kernel":  9,
	"systemd": 7,
}

// calculatePackageImportance calculates a score indicating package importance.
func calculatePackageImportance(pkg v1alpha1.PackageInfo) int {
	score := 0
	nameLower := strings.ToLower(pkg.Name)

	for keyword, weight := range _importanceKeywords {
		if strings.Contains(nameLower, keyword) {
			score += weight
		}
	}

	if pkg.Critical {
		score += 20
	}

	score += pkg.VulnerabilityCount

	if _systemPackageTypes[pkg.Type] {
		score += 2
	}

	return score
}

// EnrichWithVulnerabilities enriches SBOM packages with vulnerability information.
func (a *Analyzer) EnrichWithVulnerabilities(
	sbom *v1alpha1.SBOMInfo,
	vulnSummary *v1alpha1.VulnerabilitySummary,
) {
	if sbom == nil || vulnSummary == nil || len(vulnSummary.TopCVEs) == 0 {
		return
	}

	vulnByPackage := make(map[string][]v1alpha1.CVEInfo)
	for _, cve := range vulnSummary.TopCVEs {
		vulnByPackage[cve.Package] = append(vulnByPackage[cve.Package], cve)
	}

	for i := range sbom.Packages {
		pkg := &sbom.Packages[i]

		if vulns, ok := vulnByPackage[pkg.Name]; ok {
			pkg.VulnerabilityCount = len(vulns)

			for _, vuln := range vulns {
				if vuln.Severity == "CRITICAL" {
					pkg.Critical = true
					break
				}
			}
		}
	}
}
