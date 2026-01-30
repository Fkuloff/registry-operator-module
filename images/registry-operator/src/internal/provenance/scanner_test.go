package provenance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
)

func TestParseInTotoStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		giveData      string
		wantType      string
		wantPredicate string
		wantErr       bool
	}{
		{
			name: "valid v0.1 statement",
			giveData: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"predicate": {"builder": {"id": "test"}}
			}`,
			wantType:      "https://in-toto.io/Statement/v0.1",
			wantPredicate: "https://slsa.dev/provenance/v0.2",
		},
		{
			name: "valid v1 statement",
			giveData: `{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"predicate": {}
			}`,
			wantType:      "https://in-toto.io/Statement/v1",
			wantPredicate: "https://slsa.dev/provenance/v1",
		},
		{
			name:     "invalid json",
			giveData: `{invalid`,
			wantErr:  true,
		},
		{
			name:     "empty json",
			giveData: `{}`,
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stmt, err := parseInTotoStatement([]byte(tt.giveData))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantType, stmt.Type)
			assert.Equal(t, tt.wantPredicate, stmt.PredicateType)
		})
	}
}

func TestIsSLSAProvenancePredicate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{"v0.2", "https://slsa.dev/provenance/v0.2", true},
		{"v1", "https://slsa.dev/provenance/v1", true},
		{"v1.0", "https://slsa.dev/provenance/v1.0", true},
		{"future version", "https://slsa.dev/provenance/v2", true},
		{"other predicate", "https://example.com/other", false},
		{"empty", "", false},
		{"partial match", "slsa.dev/provenance", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isSLSAProvenancePredicate(tt.give))
		})
	}
}

func TestDeriveSLSALevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		giveID    string
		wantLevel int
	}{
		{
			name:      "empty builder",
			giveID:    "",
			wantLevel: 0,
		},
		{
			name:      "known L3 github generator container",
			giveID:    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml",
			wantLevel: 3,
		},
		{
			name:      "known L3 github generator go",
			giveID:    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
			wantLevel: 3,
		},
		{
			name:      "google cloud build L3",
			giveID:    "https://cloudbuild.googleapis.com/GoogleHostedWorker",
			wantLevel: 3,
		},
		{
			name:      "slsa framework generic - L2",
			giveID:    "https://github.com/slsa-framework/generic-generator",
			wantLevel: 2,
		},
		{
			name:      "cloud build generic - L2",
			giveID:    "https://cloudbuild.googleapis.com/something-else",
			wantLevel: 2,
		},
		{
			name:      "unknown builder - L1",
			giveID:    "https://custom-builder.example.com",
			wantLevel: 1,
		},
		{
			name:      "jenkins builder - L1",
			giveID:    "https://jenkins.io/builder",
			wantLevel: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantLevel, deriveSLSALevel(tt.giveID))
		})
	}
}

func TestCleanGitURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{
			name: "git+ prefix with refs/tags",
			give: "git+https://github.com/org/repo@refs/tags/v1.0.0",
			want: "https://github.com/org/repo",
		},
		{
			name: "plain https",
			give: "https://github.com/org/repo",
			want: "https://github.com/org/repo",
		},
		{
			name: "git+ prefix only",
			give: "git+https://github.com/org/repo",
			want: "https://github.com/org/repo",
		},
		{
			name: "with refs/heads",
			give: "https://github.com/org/repo@refs/heads/main",
			want: "https://github.com/org/repo",
		},
		{
			name: "with refs/pull",
			give: "git+https://github.com/org/repo@refs/pull/123/head",
			want: "https://github.com/org/repo",
		},
		{
			name: "empty string",
			give: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, cleanGitURI(tt.give))
		})
	}
}

//nolint:funlen // table-driven test with JSON payloads
func TestExtractV02Provenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		givePred    string
		wantBuilder string
		wantRepo    string
		wantCommit  string
		wantSLSA    int
	}{
		{
			name: "full provenance with configSource",
			givePred: `{
				"builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"},
				"invocation": {
					"configSource": {
						"uri": "git+https://github.com/org/repo@refs/tags/v1.0",
						"digest": {"sha1": "abc123def456"}
					}
				},
				"materials": []
			}`,
			wantBuilder: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml",
			wantRepo:    "https://github.com/org/repo",
			wantCommit:  "abc123def456",
			wantSLSA:    3,
		},
		{
			name: "provenance with materials only",
			givePred: `{
				"builder": {"id": "custom-builder"},
				"invocation": {"configSource": {}},
				"materials": [
					{
						"uri": "https://github.com/org/repo",
						"digest": {"sha1": "def456ghi789"}
					}
				]
			}`,
			wantBuilder: "custom-builder",
			wantRepo:    "https://github.com/org/repo",
			wantCommit:  "def456ghi789",
			wantSLSA:    1,
		},
		{
			name: "minimal provenance - builder only",
			givePred: `{
				"builder": {"id": "https://github.com/slsa-framework/other-generator"},
				"invocation": {},
				"materials": []
			}`,
			wantBuilder: "https://github.com/slsa-framework/other-generator",
			wantRepo:    "",
			wantCommit:  "",
			wantSLSA:    2,
		},
		{
			name:        "empty predicate",
			givePred:    `{}`,
			wantBuilder: "",
			wantRepo:    "",
			wantCommit:  "",
			wantSLSA:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			info := &v1alpha1.ProvenanceInfo{}

			extractV02Provenance(json.RawMessage(tt.givePred), info)

			assert.Equal(t, tt.wantBuilder, info.Builder)
			assert.Equal(t, tt.wantRepo, info.SourceRepo)
			assert.Equal(t, tt.wantCommit, info.SourceCommit)
			assert.Equal(t, tt.wantSLSA, info.SLSALevel)
		})
	}
}

//nolint:funlen // table-driven test with JSON payloads
func TestExtractV1Provenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		givePred    string
		wantBuilder string
		wantRepo    string
		wantCommit  string
		wantSLSA    int
	}{
		{
			name: "full v1 provenance",
			givePred: `{
				"buildDefinition": {
					"buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
					"resolvedDependencies": [
						{
							"uri": "git+https://github.com/org/repo@refs/heads/main",
							"digest": {"sha1": "abc123"}
						}
					]
				},
				"runDetails": {
					"builder": {
						"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"
					}
				}
			}`,
			wantBuilder: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml",
			wantRepo:    "https://github.com/org/repo",
			wantCommit:  "abc123",
			wantSLSA:    3,
		},
		{
			name: "v1 provenance with gitCommit digest",
			givePred: `{
				"buildDefinition": {
					"resolvedDependencies": [
						{
							"uri": "https://github.com/org/repo",
							"digest": {"gitCommit": "xyz789"}
						}
					]
				},
				"runDetails": {
					"builder": {"id": "custom-builder"}
				}
			}`,
			wantBuilder: "custom-builder",
			wantRepo:    "https://github.com/org/repo",
			wantCommit:  "xyz789",
			wantSLSA:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			info := &v1alpha1.ProvenanceInfo{}

			extractV1Provenance(json.RawMessage(tt.givePred), info)

			assert.Equal(t, tt.wantBuilder, info.Builder)
			assert.Equal(t, tt.wantRepo, info.SourceRepo)
			assert.Equal(t, tt.wantCommit, info.SourceCommit)
			assert.Equal(t, tt.wantSLSA, info.SLSALevel)
		})
	}
}

func TestIsAttestationType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		giveType   string
		giveAnnots map[string]string
		want       bool
	}{
		{"in-toto attestation", "application/vnd.in-toto+json", nil, true},
		{"generic attestation", "application/attestation+json", nil, true},
		{"with predicate annotation", "", map[string]string{"predicateType": "https://slsa.dev/provenance/v0.2"}, true},
		{"dsse envelope", "application/vnd.dsse.envelope.v1+json", nil, false},
		{"empty", "", nil, false},
		{"image manifest", "application/vnd.oci.image.manifest.v1+json", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isAttestationType(tt.giveType, tt.giveAnnots))
		})
	}
}

func TestIsSignatureType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{"cosign signature", "application/vnd.dev.cosign.simplesigning.v1+json", true},
		{"generic signature", "application/signature+json", true},
		{"cosign artifact", "dev.cosign.artifact", true},
		{"attestation", "application/attestation+json", false},
		{"empty", "", false},
		{"image config", "application/vnd.oci.image.config.v1+json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isSignatureType(tt.give))
		})
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(Config{})

		assert.NotNil(t, scanner)
		assert.Equal(t, 30*time.Second, scanner.timeout)
		assert.NotNil(t, scanner.auth)
	})

	t.Run("custom timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(Config{
			Timeout: 60 * time.Second,
		})

		assert.Equal(t, 60*time.Second, scanner.timeout)
	})
}

func TestNewEmptyProvenance(t *testing.T) {
	t.Parallel()

	info := newEmptyProvenance()

	assert.NotNil(t, info)
	assert.NotNil(t, info.LastCheckTime)
	assert.Empty(t, info.Builder)
	assert.Empty(t, info.SourceRepo)
	assert.Empty(t, info.SourceCommit)
	assert.Equal(t, 0, info.SLSALevel)
	assert.False(t, info.Signed)
}
