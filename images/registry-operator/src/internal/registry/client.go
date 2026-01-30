// Package registry provides a client for interacting with Docker Registry API v2.
package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

// ExtendedImageDetails contains full metadata about a container image.
type ExtendedImageDetails struct {
	Tag        string
	Digest     string
	Size       int64
	Created    *time.Time
	Platforms  []string
	Config     *ImageConfigDetails
	LayerCount int
}

// ImageConfigDetails contains configuration extracted from the image.
type ImageConfigDetails struct {
	BaseImage    string
	Author       string
	User         string
	WorkDir      string
	Entrypoint   []string
	Cmd          []string
	ExposedPorts []string
	EnvVars      []string
	Labels       map[string]string
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

	// #nosec G402 -- InsecureSkipVerify is explicitly configurable by the user via the Registry CR
	// for testing with self-signed certificates or insecure registries. This is intentional and documented.
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

// GetExtendedImageDetails fetches complete metadata for a specific image tag.
func (c *Client) GetExtendedImageDetails(ctx context.Context, repository, tag string) (*ExtendedImageDetails, error) {
	tagRef, err := c.parseTag(repository, tag)
	if err != nil {
		return nil, err
	}

	opts := c.buildOptions(ctx)
	desc, err := remote.Get(tagRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("get image: %w", err)
	}

	result := &ExtendedImageDetails{
		Tag:    tag,
		Digest: desc.Digest.String(),
	}

	// Try to get as image index (multi-arch) first
	platforms, err := c.getPlatforms(desc)
	if err == nil {
		result.Platforms = platforms
	}

	// Get image (for single arch or first platform)
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("parse image: %w", err)
	}

	// Get manifest for size calculation
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	result.Size = manifest.Config.Size
	for _, layer := range manifest.Layers {
		result.Size += layer.Size
	}
	result.LayerCount = len(manifest.Layers)

	// Get image config for metadata
	configFile, err := img.ConfigFile()
	if err == nil && configFile != nil {
		result.Created = extractCreatedTime(configFile.Created)
		result.Config = extractImageConfig(configFile)
	}

	return result, nil
}

// extractCreatedTime safely extracts the created time from image config.
func extractCreatedTime(created v1.Time) *time.Time {
	t := created.Time
	if !t.IsZero() {
		return &t
	}
	return nil
}

// extractImageConfig extracts configuration details from image config file.
func extractImageConfig(configFile *v1.ConfigFile) *ImageConfigDetails {
	if configFile == nil {
		return nil
	}

	cfg := &ImageConfigDetails{
		Author:       configFile.Author,
		User:         configFile.Config.User,
		WorkDir:      configFile.Config.WorkingDir,
		Entrypoint:   configFile.Config.Entrypoint,
		Cmd:          configFile.Config.Cmd,
		ExposedPorts: make([]string, 0),
		EnvVars:      make([]string, 0),
		Labels:       make(map[string]string),
	}

	// Extract exposed ports
	for port := range configFile.Config.ExposedPorts {
		cfg.ExposedPorts = append(cfg.ExposedPorts, port)
	}
	sort.Strings(cfg.ExposedPorts)

	// Extract environment variable names (not values for security)
	for _, env := range configFile.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) > 0 && parts[0] != "" {
			cfg.EnvVars = append(cfg.EnvVars, parts[0])
		}
	}
	sort.Strings(cfg.EnvVars)

	// Extract labels
	for k, v := range configFile.Config.Labels {
		cfg.Labels[k] = v
	}

	// Try to extract base image from labels
	if baseImage, ok := cfg.Labels["org.opencontainers.image.base.name"]; ok {
		cfg.BaseImage = baseImage
	}

	return cfg
}

// getPlatforms extracts platform information from an image index.
func (c *Client) getPlatforms(desc *remote.Descriptor) ([]string, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		// Not a multi-arch image, try to get platform from single image
		return c.getPlatformFromSingleImage(desc, err)
	}

	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("get index manifest: %w", err)
	}

	platforms := make([]string, 0, len(indexManifest.Manifests))
	for _, m := range indexManifest.Manifests {
		if m.Platform != nil {
			platforms = append(platforms, formatPlatform(m.Platform.OS, m.Platform.Architecture, m.Platform.Variant))
		}
	}

	sort.Strings(platforms)
	return platforms, nil
}

// getPlatformFromSingleImage extracts platform from a single image when index is not available.
func (c *Client) getPlatformFromSingleImage(desc *remote.Descriptor, originalErr error) ([]string, error) {
	img, err := desc.Image()
	if err != nil {
		return nil, originalErr
	}

	configFile, err := img.ConfigFile()
	if err != nil || configFile == nil {
		return nil, originalErr
	}

	if configFile.OS == "" || configFile.Architecture == "" {
		return nil, originalErr
	}

	return []string{formatPlatform(configFile.OS, configFile.Architecture, configFile.Variant)}, nil
}

// formatPlatform formats OS, architecture, and optional variant into a platform string.
func formatPlatform(os, arch, variant string) string {
	platform := os + "/" + arch
	if variant != "" {
		platform += "/" + variant
	}
	return platform
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
