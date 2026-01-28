// Package sbom provides SBOM generation and analysis functionality.
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// SyftConfig contains configuration for Syft SBOM scanner.
type SyftConfig struct {
	// Format is the output format (spdx-json, cyclonedx-json, syft-json).
	Format string

	// Timeout is the maximum time to wait for SBOM generation.
	Timeout time.Duration

	// IncludeLicenses includes license information.
	IncludeLicenses bool
}

// Scanner generates SBOM for container images.
type Scanner struct {
	config SyftConfig
}

// NewScanner creates a new SBOM scanner with the given configuration.
func NewScanner(config SyftConfig) *Scanner {
	if config.Format == "" {
		config.Format = "syft-json"
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}
	return &Scanner{
		config: config,
	}
}

// CheckSyftInstalled verifies that Syft is installed and available.
func CheckSyftInstalled() error {
	cmd := exec.Command("syft", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("syft not found in PATH: %w (install from https://github.com/anchore/syft)", err)
	}
	return nil
}

// Scan generates SBOM for the specified container image.
func (s *Scanner) Scan(ctx context.Context, imageRef string) (*v1alpha1.SBOMInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	args := []string{
		"scan",
		imageRef,
		"-o", s.config.Format,
		"--quiet",
	}

	cmd := exec.CommandContext(ctx, "syft", args...)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("syft scan failed: %w (stderr: %s)", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("syft scan failed: %w", err)
	}

	return s.parseSyftOutput(output)
}

// syftDocument represents the Syft JSON output structure.
type syftDocument struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Type     string        `json:"type"`
	Licenses []syftLicense `json:"licenses"`
}

type syftLicense struct {
	Value string `json:"value"`
}

// parseSyftOutput parses Syft JSON output into SBOMInfo.
func (s *Scanner) parseSyftOutput(output []byte) (*v1alpha1.SBOMInfo, error) {
	var doc syftDocument
	if err := json.Unmarshal(output, &doc); err != nil {
		return nil, fmt.Errorf("parse syft output: %w", err)
	}

	now := metav1.Now()
	sbomInfo := &v1alpha1.SBOMInfo{
		Format:        s.config.Format,
		GeneratedAt:   &now,
		TotalPackages: len(doc.Artifacts),
		PackageTypes:  make(map[string]int),
	}

	packages := make([]v1alpha1.PackageInfo, 0, len(doc.Artifacts))
	licenseMap := make(map[string]int)
	var totalLicensed int

	for _, artifact := range doc.Artifacts {
		pkg := v1alpha1.PackageInfo{
			Name:    artifact.Name,
			Version: artifact.Version,
			Type:    artifact.Type,
		}

		// Process licenses if enabled
		if s.config.IncludeLicenses {
			var licenses []string
			for _, lic := range artifact.Licenses {
				if lic.Value != "" {
					licenses = append(licenses, lic.Value)
					licenseMap[lic.Value]++
				}
			}
			if len(licenses) > 0 {
				pkg.License = strings.Join(licenses, ", ")
				totalLicensed++
			}
		}

		packages = append(packages, pkg)

		if artifact.Type != "" {
			sbomInfo.PackageTypes[artifact.Type]++
		}
	}

	sbomInfo.Packages = packages

	if s.config.IncludeLicenses {
		sbomInfo.Licenses = &v1alpha1.LicenseSummary{
			Total:     totalLicensed,
			Unknown:   len(doc.Artifacts) - totalLicensed,
			ByLicense: licenseMap,
		}

		sbomInfo.Licenses.RiskyLicenses = identifyRiskyLicenses(licenseMap)
	}

	return sbomInfo, nil
}

// _riskyLicensePatterns contains patterns for licenses that may pose compliance risks.
var _riskyLicensePatterns = []string{
	"GPL", "AGPL", "LGPL", // Copyleft licenses
	"SSPL",           // Server Side Public License
	"Commons Clause", // Restrictive
}

// identifyRiskyLicenses identifies licenses that may pose compliance risks.
func identifyRiskyLicenses(licenseMap map[string]int) []string {
	var risky []string
	for license := range licenseMap {
		if isRiskyLicense(license) {
			risky = append(risky, license)
		}
	}
	return risky
}

func isRiskyLicense(license string) bool {
	licenseUpper := strings.ToUpper(license)
	for _, pattern := range _riskyLicensePatterns {
		if strings.Contains(licenseUpper, pattern) {
			return true
		}
	}
	return false
}
