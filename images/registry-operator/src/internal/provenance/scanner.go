// Package provenance provides image provenance tracking using OCI referrers.
package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

// Predicate types for SLSA provenance.
const (
	_predicateTypeSLSAv02 = "https://slsa.dev/provenance/v0.2"
	_predicateTypeSLSAv1  = "https://slsa.dev/provenance/v1"

	_maxAttestationSize = 1024 * 1024 // 1MB limit for attestation payload
)

// Known SLSA L3 builders.
var _knownSLSA3Builders = map[string]bool{
	"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml": true,
	"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml":          true,
	"https://cloudbuild.googleapis.com/GoogleHostedWorker":                                                    true,
}

// Scanner scans images for provenance attestations.
type Scanner struct {
	auth    authn.Authenticator
	timeout time.Duration
}

// Config holds configuration for the provenance scanner.
type Config struct {
	// Auth is the authenticator for registry access.
	Auth authn.Authenticator

	// Timeout is the scan timeout.
	Timeout time.Duration
}

// NewScanner creates a new provenance scanner.
func NewScanner(cfg Config) *Scanner {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	auth := cfg.Auth
	if auth == nil {
		auth = authn.Anonymous
	}

	return &Scanner{
		auth:    auth,
		timeout: timeout,
	}
}

// Scan retrieves provenance information for an image digest.
// imageRef should include the digest: "registry/repo@sha256:..."
func (s *Scanner) Scan(ctx context.Context, imageRef string) (*v1alpha1.ProvenanceInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	digestRef, err := name.NewDigest(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse digest reference: %w", err)
	}

	opts := []remote.Option{
		remote.WithAuth(s.auth),
		remote.WithContext(ctx),
	}

	// Fetch referrers (attestations attached to this image)
	idx, err := remote.Referrers(digestRef, opts...)
	if err != nil {
		// Not all registries support referrers - return empty provenance
		return newEmptyProvenance(), nil
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return newEmptyProvenance(), nil
	}

	info := newEmptyProvenance()

	// Scan through referrers for provenance attestations
	for _, desc := range manifest.Manifests {
		artifactType := desc.ArtifactType
		if artifactType == "" {
			// Check annotations for older format
			if at, ok := desc.Annotations["org.opencontainers.image.type"]; ok {
				artifactType = at
			}
		}

		// Check for signature attestations
		if isSignatureType(artifactType) {
			info.Signed = true
		}

		// Look for attestation manifests
		if !isAttestationType(artifactType, desc.Annotations) {
			continue
		}

		// Fetch the attestation
		attestation, err := s.fetchAttestation(ctx, digestRef, desc.Digest.String(), opts)
		if err != nil {
			continue
		}

		// Parse in-toto statement
		statement, err := parseInTotoStatement(attestation)
		if err != nil {
			continue
		}

		// Check if it's a provenance predicate
		if isSLSAProvenancePredicate(statement.PredicateType) {
			extractProvenanceInfo(statement, info)
		}
	}

	return info, nil
}

// newEmptyProvenance returns an empty provenance info with timestamp.
func newEmptyProvenance() *v1alpha1.ProvenanceInfo {
	now := metav1.Now()
	return &v1alpha1.ProvenanceInfo{
		LastCheckTime: &now,
	}
}

// fetchAttestation retrieves attestation payload from a referrer.
func (s *Scanner) fetchAttestation(
	_ context.Context,
	base name.Digest,
	attestDigest string,
	opts []remote.Option,
) ([]byte, error) {
	// Construct reference to the attestation
	attestRef, err := name.NewDigest(fmt.Sprintf("%s@%s", base.Repository.String(), attestDigest))
	if err != nil {
		return nil, err
	}

	img, err := remote.Image(attestRef, opts...)
	if err != nil {
		return nil, err
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("no layers in attestation")
	}

	// Attestation payload is typically in the first layer
	layer := layers[0]
	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	// Read the payload (limited to prevent OOM)
	limitedReader := io.LimitReader(reader, _maxAttestationSize)
	return io.ReadAll(limitedReader)
}

// inTotoStatement represents an in-toto attestation statement.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// slsaProvenanceV02 represents SLSA v0.2 provenance predicate.
type slsaProvenanceV02 struct {
	Builder struct {
		ID string `json:"id"`
	} `json:"builder"`
	Invocation struct {
		ConfigSource struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"configSource"`
	} `json:"invocation"`
	Materials []struct {
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	} `json:"materials"`
}

// slsaProvenanceV1 represents SLSA v1.0 provenance predicate.
type slsaProvenanceV1 struct {
	BuildDefinition struct {
		BuildType            string          `json:"buildType"`
		ExternalParameters   json.RawMessage `json:"externalParameters"`
		ResolvedDependencies []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

// parseInTotoStatement parses an in-toto statement from JSON.
func parseInTotoStatement(data []byte) (*inTotoStatement, error) {
	var stmt inTotoStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal in-toto statement: %w", err)
	}
	return &stmt, nil
}

// isSLSAProvenancePredicate checks if predicate type is SLSA provenance.
func isSLSAProvenancePredicate(predicateType string) bool {
	return predicateType == _predicateTypeSLSAv02 ||
		predicateType == _predicateTypeSLSAv1 ||
		strings.HasPrefix(predicateType, "https://slsa.dev/provenance/")
}

// isAttestationType checks if artifact type indicates an attestation.
func isAttestationType(artifactType string, annotations map[string]string) bool {
	if strings.Contains(artifactType, "attestation") ||
		strings.Contains(artifactType, "in-toto") ||
		artifactType == "application/vnd.in-toto+json" {
		return true
	}

	// Check annotation for predicate type
	_, hasPredicateType := annotations["predicateType"]
	return hasPredicateType
}

// isSignatureType checks if artifact type indicates a signature.
func isSignatureType(artifactType string) bool {
	return strings.Contains(artifactType, "signature") ||
		strings.Contains(artifactType, "cosign")
}

// extractProvenanceInfo extracts minimal provenance information from statement.
func extractProvenanceInfo(stmt *inTotoStatement, info *v1alpha1.ProvenanceInfo) {
	switch stmt.PredicateType {
	case _predicateTypeSLSAv1:
		extractV1Provenance(stmt.Predicate, info)
	default:
		// v0.2 and fallback
		extractV02Provenance(stmt.Predicate, info)
	}
}

// extractV02Provenance extracts info from SLSA v0.2 predicate.
func extractV02Provenance(predicate json.RawMessage, info *v1alpha1.ProvenanceInfo) {
	var prov slsaProvenanceV02
	if err := json.Unmarshal(predicate, &prov); err != nil {
		return
	}

	info.Builder = prov.Builder.ID

	// Extract source from configSource or materials
	if prov.Invocation.ConfigSource.URI != "" {
		info.SourceRepo = cleanGitURI(prov.Invocation.ConfigSource.URI)
		if sha, ok := prov.Invocation.ConfigSource.Digest["sha1"]; ok {
			info.SourceCommit = sha
		}
	} else if len(prov.Materials) > 0 {
		info.SourceRepo = cleanGitURI(prov.Materials[0].URI)
		if sha, ok := prov.Materials[0].Digest["sha1"]; ok {
			info.SourceCommit = sha
		}
	}

	info.SLSALevel = deriveSLSALevel(info.Builder)
}

// extractV1Provenance extracts info from SLSA v1.0 predicate.
func extractV1Provenance(predicate json.RawMessage, info *v1alpha1.ProvenanceInfo) {
	var prov slsaProvenanceV1
	if err := json.Unmarshal(predicate, &prov); err != nil {
		return
	}

	info.Builder = prov.RunDetails.Builder.ID

	// Extract source from resolved dependencies
	if len(prov.BuildDefinition.ResolvedDependencies) > 0 {
		dep := prov.BuildDefinition.ResolvedDependencies[0]
		info.SourceRepo = cleanGitURI(dep.URI)
		if sha, ok := dep.Digest["sha1"]; ok {
			info.SourceCommit = sha
		} else if sha, ok := dep.Digest["gitCommit"]; ok {
			info.SourceCommit = sha
		}
	}

	info.SLSALevel = deriveSLSALevel(info.Builder)
}

// cleanGitURI removes git+ prefix and @refs suffix from URIs.
func cleanGitURI(uri string) string {
	uri = strings.TrimPrefix(uri, "git+")
	if idx := strings.Index(uri, "@refs/"); idx != -1 {
		uri = uri[:idx]
	}
	return uri
}

// deriveSLSALevel derives the SLSA level from the builder ID.
func deriveSLSALevel(builderID string) int {
	if builderID == "" {
		return 0
	}

	// Known SLSA L3 builders
	if _knownSLSA3Builders[builderID] {
		return 3
	}

	// GitHub Actions builders are typically L2
	if strings.Contains(builderID, "github.com/slsa-framework") {
		return 2
	}

	// Google Cloud Build
	if strings.Contains(builderID, "cloudbuild.googleapis.com") {
		return 2
	}

	// Any provenance attestation indicates at least L1
	return 1
}
