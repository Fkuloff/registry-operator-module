// Package sbom provides SBOM generation and analysis functionality.
package sbom

import (
	"context"
	"encoding/json"
	"errors"
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

	// Validate imageRef to prevent command injection
	if strings.ContainsAny(imageRef, "&|;<>$`\n") {
		return nil, fmt.Errorf("invalid image reference: contains prohibited characters")
	}

	args := []string{
		"scan",
		imageRef,
		"-o", s.config.Format,
		"--quiet",
	}

	// #nosec G204 -- imageRef is validated above to prevent injection, and syft is a required
	// external tool for SBOM generation. Arguments are constructed from validated inputs only.
	cmd := exec.CommandContext(ctx, "syft", args...)

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
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

	for _, artifact := range doc.Artifacts {
		pkg := v1alpha1.PackageInfo{
			Name:    artifact.Name,
			Version: artifact.Version,
			Type:    artifact.Type,
		}

		packages = append(packages, pkg)

		if artifact.Type != "" {
			sbomInfo.PackageTypes[artifact.Type]++
		}
	}

	sbomInfo.Packages = packages

	return sbomInfo, nil
}
