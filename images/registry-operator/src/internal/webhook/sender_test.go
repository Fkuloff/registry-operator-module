package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSender(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give Config
		want struct {
			hasAuthHeader bool
			authPrefix    string
		}
	}{
		{
			name: "no auth",
			give: Config{
				URL: "https://example.com/webhook",
			},
			want: struct {
				hasAuthHeader bool
				authPrefix    string
			}{
				hasAuthHeader: false,
			},
		},
		{
			name: "bearer auth",
			give: Config{
				URL:       "https://example.com/webhook",
				AuthType:  "bearer",
				AuthToken: "secret-token",
			},
			want: struct {
				hasAuthHeader bool
				authPrefix    string
			}{
				hasAuthHeader: true,
				authPrefix:    "Bearer ",
			},
		},
		{
			name: "basic auth",
			give: Config{
				URL:          "https://example.com/webhook",
				AuthType:     "basic",
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			want: struct {
				hasAuthHeader bool
				authPrefix    string
			}{
				hasAuthHeader: true,
				authPrefix:    "Basic ",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sender := NewSender(tt.give)

			assert.Equal(t, tt.give.URL, sender.url)
			if tt.want.hasAuthHeader {
				assert.NotEmpty(t, sender.authHeader)
				assert.Contains(t, sender.authHeader, tt.want.authPrefix)
			} else {
				assert.Empty(t, sender.authHeader)
			}
		})
	}
}

func TestSender_Send(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		givePayload   *Payload
		giveAuthType  string
		giveAuthToken string
		serverStatus  int
		wantErr       bool
		wantErrMsg    string
	}{
		{
			name: "successful send",
			givePayload: &Payload{
				Event:     "scan-completed",
				Timestamp: time.Now().Format(time.RFC3339),
				Registry: RegistryInfo{
					Name:       "test-registry",
					Namespace:  "default",
					URL:        "https://registry.example.com",
					Repository: "library/nginx",
				},
				Data: &ScanCompletedData{
					ImagesScanned: 5,
					Vulnerabilities: &VulnerabilitySummary{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      4,
						Total:    10,
					},
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name: "successful send with bearer auth",
			givePayload: &Payload{
				Event:     "vulnerability-critical",
				Timestamp: time.Now().Format(time.RFC3339),
				Registry: RegistryInfo{
					Name:      "test-registry",
					Namespace: "default",
				},
			},
			giveAuthType:  "bearer",
			giveAuthToken: "test-token",
			serverStatus:  http.StatusAccepted,
			wantErr:       false,
		},
		{
			name: "server error",
			givePayload: &Payload{
				Event: "scan-completed",
			},
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
			wantErrMsg:   "unexpected status code: 500",
		},
		{
			name: "unauthorized",
			givePayload: &Payload{
				Event: "scan-completed",
			},
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
			wantErrMsg:   "unexpected status code: 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var receivedPayload Payload
			var receivedAuthHeader string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.Contains(t, r.Header.Get("User-Agent"), "registry-operator")

				receivedAuthHeader = r.Header.Get("Authorization")

				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if err = json.Unmarshal(body, &receivedPayload); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				w.WriteHeader(tt.serverStatus)
			}))
			defer server.Close()

			sender := NewSender(Config{
				URL:       server.URL,
				AuthType:  tt.giveAuthType,
				AuthToken: tt.giveAuthToken,
				Timeout:   5 * time.Second,
			})

			ctx := context.Background()
			err := sender.Send(ctx, tt.givePayload)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.givePayload.Event, receivedPayload.Event)

			if tt.giveAuthType == "bearer" {
				assert.Equal(t, "Bearer "+tt.giveAuthToken, receivedAuthHeader)
			}
		})
	}
}

func TestSender_Send_ContextCanceled(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewSender(Config{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sender.Send(ctx, &Payload{Event: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestBuildAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give Config
		want string
	}{
		{
			name: "no auth",
			give: Config{},
			want: "",
		},
		{
			name: "bearer with token",
			give: Config{
				AuthType:  "bearer",
				AuthToken: "my-token",
			},
			want: "Bearer my-token",
		},
		{
			name: "bearer without token",
			give: Config{
				AuthType: "bearer",
			},
			want: "",
		},
		{
			name: "basic auth",
			give: Config{
				AuthType:     "basic",
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			want: "Basic dXNlcjpwYXNz", // base64("user:pass")
		},
		{
			name: "basic without username",
			give: Config{
				AuthType:     "basic",
				AuthPassword: "pass",
			},
			want: "",
		},
		{
			name: "unknown auth type",
			give: Config{
				AuthType:  "unknown",
				AuthToken: "token",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildAuthHeader(tt.give)
			assert.Equal(t, tt.want, got)
		})
	}
}
