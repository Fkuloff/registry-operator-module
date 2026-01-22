package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Client struct {
	registryURL   string
	remoteOptions []remote.Option
}

type ImageDetails struct {
	Tag    string
	Digest string
	Size   int64
}

func NewClient(registryURL, username, password string, insecureSkipVerify bool) *Client {
	authenticator := authn.Anonymous
	if username != "" {
		authenticator = authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
	}

	remoteOptions := []remote.Option{
		remote.WithAuth(authenticator),
	}

	if insecureSkipVerify {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOptions = append(remoteOptions, remote.WithTransport(transport))
	}

	return &Client{
		registryURL:   registryURL,
		remoteOptions: remoteOptions,
	}
}

func (c *Client) ListTags(ctx context.Context, repository string) ([]string, error) {
	repo, err := c.parseRepository(repository)
	if err != nil {
		return nil, err
	}

	options := c.buildOptions(ctx)
	tags, err := remote.List(repo, options...)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	return tags, nil
}

func (c *Client) GetImageDetails(ctx context.Context, repository, tag string) (*ImageDetails, error) {
	tagRef, err := c.parseTag(repository, tag)
	if err != nil {
		return nil, err
	}

	options := c.buildOptions(ctx)
	descriptor, err := remote.Get(tagRef, options...)
	if err != nil {
		return nil, fmt.Errorf("get image: %w", err)
	}

	image, err := descriptor.Image()
	if err != nil {
		return nil, fmt.Errorf("parse image: %w", err)
	}

	manifest, err := image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	totalSize := manifest.Config.Size
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}

	return &ImageDetails{
		Tag:    tag,
		Digest: descriptor.Digest.String(),
		Size:   totalSize,
	}, nil
}

func (c *Client) buildOptions(ctx context.Context) []remote.Option {
	options := make([]remote.Option, len(c.remoteOptions), len(c.remoteOptions)+1)
	copy(options, c.remoteOptions)
	return append(options, remote.WithContext(ctx))
}

func (c *Client) parseRepository(repository string) (name.Repository, error) {
	fullPath := fmt.Sprintf("%s/%s", c.registryURL, repository)
	return name.NewRepository(fullPath, name.Insecure)
}

func (c *Client) parseTag(repository, tag string) (name.Tag, error) {
	fullRef := fmt.Sprintf("%s/%s:%s", c.registryURL, repository, tag)
	return name.NewTag(fullRef, name.Insecure)
}
