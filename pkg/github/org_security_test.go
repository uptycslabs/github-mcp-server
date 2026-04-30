package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/github/github-mcp-server/internal/toolsnaps"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const getOrgsMembersByOrg = "GET /orgs/{org}/members"

func Test_ListOrgAdmins(t *testing.T) {
	toolDef := ListOrgAdmins(translations.NullTranslationHelper)
	require.NoError(t, toolsnaps.Test(toolDef.Tool.Name, toolDef.Tool))

	assert.Equal(t, "list_org_admins", toolDef.Tool.Name)
	assert.NotEmpty(t, toolDef.Tool.Description)

	schema, ok := toolDef.Tool.InputSchema.(*jsonschema.Schema)
	require.True(t, ok)
	assert.Contains(t, schema.Properties, "org")
	assert.ElementsMatch(t, schema.Required, []string{"org"})

	mockAdmins := []*github.User{
		{Login: github.Ptr("admin1"), ID: github.Ptr(int64(1))},
		{Login: github.Ptr("admin2"), ID: github.Ptr(int64(2))},
	}

	tests := []struct {
		name              string
		mockedClient      *http.Client
		requestArgs       map[string]any
		expectError       bool
		expectedErrMsg    string
		expectedRoleParam string // verified by handler when set
	}{
		{
			name: "successful listing — handler must pass role=admin",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				getOrgsMembersByOrg: func(w http.ResponseWriter, r *http.Request) {
					// Verify the role filter actually reached the API.
					q, _ := url.ParseQuery(r.URL.RawQuery)
					assert.Equal(t, "admin", q.Get("role"), "list_org_admins must request role=admin")
					mockResponse(t, http.StatusOK, mockAdmins)(w, r)
				},
			}),
			requestArgs: map[string]any{"org": "test-org"},
		},
		{
			name: "API returns 403 — propagates as tool error",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				getOrgsMembersByOrg: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
				},
			}),
			requestArgs:    map[string]any{"org": "test-org"},
			expectError:    true,
			expectedErrMsg: "failed to list org admins",
		},
		{
			name:           "missing required org",
			mockedClient:   MockHTTPClientWithHandlers(map[string]http.HandlerFunc{}),
			requestArgs:    map[string]any{},
			expectError:    true,
			expectedErrMsg: "org",
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

			var users []*github.User
			require.NoError(t, json.Unmarshal([]byte(textContent.Text), &users))
			assert.Len(t, users, 2)
			assert.Equal(t, "admin1", users[0].GetLogin())
		})
	}
}
