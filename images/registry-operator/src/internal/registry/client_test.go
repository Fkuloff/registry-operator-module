package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripScheme(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "https scheme",
			input:    "https://registry.example.com",
			expected: "registry.example.com",
		},
		{
			name:     "http scheme",
			input:    "http://registry.example.com",
			expected: "registry.example.com",
		},
		{
			name:     "no scheme",
			input:    "registry.example.com",
			expected: "registry.example.com",
		},
		{
			name:     "localhost with port and https",
			input:    "https://localhost:5000",
			expected: "localhost:5000",
		},
		{
			name:     "localhost with port and http",
			input:    "http://localhost:5000",
			expected: "localhost:5000",
		},
		{
			name:     "registry with port",
			input:    "https://registry.example.com:443",
			expected: "registry.example.com:443",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only https://",
			input:    "https://",
			expected: "",
		},
		{
			name:     "docker hub",
			input:    "https://index.docker.io",
			expected: "index.docker.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripScheme(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestParseRepository(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		repo        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "simple repository",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			wantErr: false,
		},
		{
			name:    "repository with path",
			url:     "https://registry.example.com",
			repo:    "library/nginx",
			wantErr: false,
		},
		{
			name:    "repository with deep path",
			url:     "https://registry.example.com",
			repo:    "org/team/project",
			wantErr: false,
		},
		{
			name:    "docker hub shorthand",
			url:     "https://index.docker.io",
			repo:    "nginx",
			wantErr: false,
		},
		{
			name:    "localhost registry",
			url:     "http://localhost:5000",
			repo:    "test-image",
			wantErr: false,
		},
		{
			name:    "no scheme in url",
			url:     "registry.example.com",
			repo:    "myrepo",
			wantErr: false,
		},
		{
			name:        "empty repository",
			url:         "https://registry.example.com",
			repo:        "",
			wantErr:     true,
			errContains: "repository",
		},
		{
			name:    "repository with special chars",
			url:     "https://registry.example.com",
			repo:    "my-repo_123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(tt.url, "", "", false)
			ref, err := c.parseRepository(tt.repo)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, ref)
			assert.Contains(t, ref.String(), tt.repo)
		})
	}
}

//nolint:funlen // table-driven test with many cases
func TestParseTag(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		repo        string
		tag         string
		wantErr     bool
		errContains string
	}{
		{
			name:    "simple tag",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			tag:     "v1.0.0",
			wantErr: false,
		},
		{
			name:    "latest tag",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			tag:     "latest",
			wantErr: false,
		},
		{
			name:    "tag with path repository",
			url:     "https://registry.example.com",
			repo:    "library/nginx",
			tag:     "1.21-alpine",
			wantErr: false,
		},
		{
			name:    "tag with special version",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			tag:     "v1.0.0-rc.1",
			wantErr: false,
		},
		{
			name:    "numeric tag",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			tag:     "123",
			wantErr: false,
		},
		{
			name:    "localhost registry with tag",
			url:     "http://localhost:5000",
			repo:    "test",
			tag:     "dev",
			wantErr: false,
		},
		{
			name:        "empty tag",
			url:         "https://registry.example.com",
			repo:        "myrepo",
			tag:         "",
			wantErr:     true,
			errContains: "tag",
		},
		{
			name:    "tag with underscore",
			url:     "https://registry.example.com",
			repo:    "myrepo",
			tag:     "release_2024",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(tt.url, "", "", false)
			ref, err := c.parseTag(tt.repo, tt.tag)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, ref)
			assert.Contains(t, ref.String(), tt.tag)
		})
	}
}
