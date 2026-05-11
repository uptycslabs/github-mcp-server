package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/internal/toolsnaps"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const getReposVulnerabilityAlertsByOwnerByRepo = "GET /repos/{owner}/{repo}/vulnerability-alerts"

func Test_GetRepoSecuritySettings(t *testing.T) {
	toolDef := GetRepoSecuritySettings(translations.NullTranslationHelper)
	require.NoError(t, toolsnaps.Test(toolDef.Tool.Name, toolDef.Tool))

	assert.Equal(t, "get_repo_security_settings", toolDef.Tool.Name)
	assert.NotEmpty(t, toolDef.Tool.Description)

	schema, ok := toolDef.Tool.InputSchema.(*jsonschema.Schema)
	require.True(t, ok)
	assert.Contains(t, schema.Properties, "owner")
	assert.Contains(t, schema.Properties, "repo")
	assert.ElementsMatch(t, schema.Required, []string{"owner", "repo"})

	mockRepo := &github.Repository{
		Name:          github.Ptr("test-repo"),
		FullName:      github.Ptr("owner/test-repo"),
		Private:       github.Ptr(true),
		Visibility:    github.Ptr("private"),
		DefaultBranch: github.Ptr("main"),
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning:              &github.SecretScanning{Status: github.Ptr("enabled")},
			SecretScanningPushProtection: &github.SecretScanningPushProtection{Status: github.Ptr("enabled")},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]any
		expectError    bool
		expectedErrMsg string
		assertFields   func(t *testing.T, out map[string]any)
	}{
		{
			name: "successful fetch with vuln alerts enabled",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposByOwnerByRepo: mockResponse(t, http.StatusOK, mockRepo),
				getReposVulnerabilityAlertsByOwnerByRepo: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent) // 204 = enabled
				},
			}),
			requestArgs: map[string]any{"owner": "owner", "repo": "test-repo"},
			assertFields: func(t *testing.T, out map[string]any) {
				assert.Equal(t, "test-repo", out["name"])
				assert.Equal(t, "private", out["visibility"])
				assert.Equal(t, "main", out["default_branch"])
				assert.Equal(t, "enabled", out["secret_scanning_push_protection_state"])
				assert.Equal(t, true, out["vulnerability_alerts_enabled"])
				assert.NotNil(t, out["security_and_analysis"])
			},
		},
		{
			name: "vuln-alerts endpoint returns 404 — surfaces as vulnerability_alerts_enabled=false",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposByOwnerByRepo: mockResponse(t, http.StatusOK, mockRepo),
				getReposVulnerabilityAlertsByOwnerByRepo: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound) // SDK parseBoolResponse maps this to false, no error
				},
			}),
			requestArgs: map[string]any{"owner": "owner", "repo": "test-repo"},
			assertFields: func(t *testing.T, out map[string]any) {
				assert.Equal(t, false, out["vulnerability_alerts_enabled"], "404 should be surfaced as feature-disabled, not an error")
			},
		},
		{
			name: "primary repository fetch fails — propagates error",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposByOwnerByRepo: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message": "Not Found"}`))
				},
			}),
			requestArgs:    map[string]any{"owner": "owner", "repo": "missing"},
			expectError:    true,
			expectedErrMsg: "failed to get repository",
		},
		{
			name:           "missing required arg",
			mockedClient:   MockHTTPClientWithHandlers(map[string]http.HandlerFunc{}),
			requestArgs:    map[string]any{"owner": "owner"},
			expectError:    true,
			expectedErrMsg: "repo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := github.NewClient(tc.mockedClient)
			deps := BaseDeps{Client: client}
			handler := toolDef.Handler(deps)
			request := createMCPRequest(tc.requestArgs)

			result, err := handler(ContextWithDeps(context.Background(), deps), &request)
			if tc.expectError {
				require.NoError(t, err)
				require.True(t, result.IsError)
				errorContent := getErrorResult(t, result)
				assert.Contains(t, errorContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			require.False(t, result.IsError)
			textContent := getTextResult(t, result)

			var out map[string]any
			require.NoError(t, json.Unmarshal([]byte(textContent.Text), &out))
			if tc.assertFields != nil {
				tc.assertFields(t, out)
			}
		})
	}
}
