// Package registry provides a client for interacting with Docker Registry API v2.
package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const _defaultTimeout = 30 * time.Second

// Client provides methods for interacting with a Docker registry.
type Client struct {
	registryURL   string
	remoteOptions []remote.Option
}

// ImageDetails contains metadata about a container image.
type ImageDetails struct {
	Tag    string
	Digest string
	Size   int64
}

// ClientOption configures a Client using the functional options pattern.
type ClientOption func(*clientConfig)

type clientConfig struct {
	timeout time.Duration
}

// WithTimeout sets the HTTP timeout for registry requests.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.timeout = timeout
	}
}

// NewClient creates a new registry client with the specified credentials and options.
// If username is empty, anonymous authentication is used.
func NewClient(registryURL, username, password string, insecureSkipVerify bool, opts ...ClientOption) *Client {
	cfg := &clientConfig{
		timeout: _defaultTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	auth := authn.Anonymous
	if username != "" {
		auth = authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		DialContext: (&net.Dialer{
			Timeout: cfg.timeout,
		}).DialContext,
		ResponseHeaderTimeout: cfg.timeout,
	}

	remoteOpts := []remote.Option{
		remote.WithAuth(auth),
		remote.WithTransport(transport),
	}

	return &Client{
		registryURL:   registryURL,
		remoteOptions: remoteOpts,
	}
}

// ListTags returns all available tags for the specified repository.
func (c *Client) ListTags(ctx context.Context, repository string) ([]string, error) {
	repo, err := c.parseRepository(repository)
	if err != nil {
		return nil, err
	}

	opts := c.buildOptions(ctx)
	tags, err := remote.List(repo, opts...)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	return tags, nil
}

// GetImageDetails fetches the digest and total size for a specific image tag.
func (c *Client) GetImageDetails(ctx context.Context, repository, tag string) (*ImageDetails, error) {
	tagRef, err := c.parseTag(repository, tag)
	if err != nil {
		return nil, err
	}

	opts := c.buildOptions(ctx)
	desc, err := remote.Get(tagRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("get image: %w", err)
	}

	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("parse image: %w", err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	totalSize := manifest.Config.Size
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}

	return &ImageDetails{
		Tag:    tag,
		Digest: desc.Digest.String(),
		Size:   totalSize,
	}, nil
}

// buildOptions creates options with context appended.
func (c *Client) buildOptions(ctx context.Context) []remote.Option {
	opts := make([]remote.Option, 0, len(c.remoteOptions)+1)
	opts = append(opts, c.remoteOptions...)
	opts = append(opts, remote.WithContext(ctx))
	return opts
}

// parseRepository constructs a full repository reference.
func (c *Client) parseRepository(repository string) (name.Repository, error) {
	host := stripScheme(c.registryURL)
	return name.NewRepository(fmt.Sprintf("%s/%s", host, repository), name.Insecure)
}

// parseTag constructs a full tag reference.
func (c *Client) parseTag(repository, tag string) (name.Tag, error) {
	host := stripScheme(c.registryURL)
	return name.NewTag(fmt.Sprintf("%s/%s:%s", host, repository, tag), name.Insecure)
}

// stripScheme removes the http:// or https:// prefix from a URL.
func stripScheme(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	return url
}
