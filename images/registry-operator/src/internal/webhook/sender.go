// Package webhook provides HTTP webhook notification functionality.
package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Default configuration values.
const (
	_defaultTimeout = 10 * time.Second
	_maxBodySize    = 1 << 20 // 1MB response limit
)

// Payload represents the webhook notification payload.
type Payload struct {
	Event     string       `json:"event"`
	Timestamp string       `json:"timestamp"`
	Registry  RegistryInfo `json:"registry"`
	Data      interface{}  `json:"data,omitempty"`
}

// RegistryInfo contains registry identification information.
type RegistryInfo struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	URL        string `json:"url"`
	Repository string `json:"repository"`
}

// ScanCompletedData contains data for scan-completed events.
type ScanCompletedData struct {
	ImagesScanned   int                   `json:"imagesScanned"`
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`
}

// VulnerabilitySummary contains vulnerability counts by severity.
type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// VulnerabilityCriticalData contains data for vulnerability-critical events.
type VulnerabilityCriticalData struct {
	AffectedImages []AffectedImage `json:"affectedImages"`
}

// AffectedImage contains information about an image with critical vulnerabilities.
type AffectedImage struct {
	Tag           string   `json:"tag"`
	Digest        string   `json:"digest,omitempty"`
	CriticalCount int      `json:"criticalCount"`
	TopCVEs       []string `json:"topCVEs,omitempty"`
}

// Config contains webhook sender configuration.
type Config struct {
	URL                string
	AuthType           string // "bearer", "basic", or empty
	AuthToken          string
	AuthUsername       string
	AuthPassword       string
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// Sender sends HTTP webhook notifications.
type Sender struct {
	url        string
	authHeader string
	httpClient *http.Client
}

// NewSender creates a new webhook sender with the given configuration.
func NewSender(cfg Config) *Sender {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = _defaultTimeout
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	s := &Sender{
		url: cfg.URL,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}

	s.authHeader = buildAuthHeader(cfg)

	return s
}

// buildAuthHeader constructs the Authorization header value.
func buildAuthHeader(cfg Config) string {
	switch cfg.AuthType {
	case "bearer":
		if cfg.AuthToken != "" {
			return "Bearer " + cfg.AuthToken
		}
	case "basic":
		if cfg.AuthUsername != "" {
			credentials := cfg.AuthUsername + ":" + cfg.AuthPassword
			encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
			return "Basic " + encoded
		}
	}
	return ""
}

// Send sends a webhook notification with the given payload.
func (s *Sender) Send(ctx context.Context, payload *Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "registry-operator/1.0")

	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read and discard body to enable connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, _maxBodySize))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
