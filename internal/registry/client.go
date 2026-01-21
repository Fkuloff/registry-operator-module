package registry

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

type ImageDetails struct {
	Tag    string
	Digest string
	Size   int64
}

func NewClient(baseURL, username, password string, insecure bool) *Client {
	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

func (c *Client) ListTags(repository string) ([]string, error) {
	var resp struct {
		Tags []string `json:"tags"`
	}
	if err := c.doRequest(fmt.Sprintf("/v2/%s/tags/list", repository), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tags, nil
}

func (c *Client) GetImageDetails(repository, tag string) (*ImageDetails, error) {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repository, tag)
	headers := map[string]string{"Accept": "application/vnd.docker.distribution.manifest.v2+json"}

	req, err := c.newRequest(path, headers)
	if err != nil {
		return nil, err
	}

	resp, err := c.doWithAuth(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var manifest struct {
		Config struct {
			Size int64 `json:"size"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	size := manifest.Config.Size
	for _, l := range manifest.Layers {
		size += l.Size
	}

	return &ImageDetails{
		Tag:    tag,
		Digest: resp.Header.Get("Docker-Content-Digest"),
		Size:   size,
	}, nil
}

func (c *Client) doRequest(path string, headers map[string]string, result any) error {
	req, err := c.newRequest(path, headers)
	if err != nil {
		return err
	}

	resp, err := c.doWithAuth(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(result)
}

func (c *Client) newRequest(path string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (c *Client) doWithAuth(req *http.Request) (*http.Response, error) {
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.authenticateBearer(resp, req); err != nil {
			return nil, err
		}
		return c.httpClient.Do(req)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	return resp, nil
}

func (c *Client) authenticateBearer(resp *http.Response, req *http.Request) error {
	auth := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(auth, "Bearer ") {
		return fmt.Errorf("unsupported auth: %s", auth)
	}

	params := parseAuthParams(auth[7:])
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("no realm in WWW-Authenticate")
	}

	tokenURL, _ := url.Parse(realm)
	q := tokenURL.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	if s := params["scope"]; s != "" {
		q.Set("scope", s)
	}
	tokenURL.RawQuery = q.Encode()

	tokenReq, _ := http.NewRequest(http.MethodGet, tokenURL.String(), nil)
	if c.username != "" {
		tokenReq.SetBasicAuth(c.username, c.password)
	}

	tokenResp, err := c.httpClient.Do(tokenReq)
	if err != nil {
		return err
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		return fmt.Errorf("token request failed: %s", body)
	}

	var tokenData struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		return err
	}

	token := tokenData.Token
	if token == "" {
		token = tokenData.AccessToken
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func parseAuthParams(s string) map[string]string {
	params := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			params[k] = strings.Trim(v, `"`)
		}
	}
	return params
}
