package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	ghErrors "github.com/github/github-mcp-server/pkg/errors"
	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/scopes"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/github/github-mcp-server/pkg/utils"
	"github.com/google/go-github/v79/github"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetRepoSecuritySettings returns the `security_and_analysis` block from a repository's
// metadata. Cheaper than asking the AI to call get_repository and pluck fields itself,
// and produces a focused payload for posture investigations.
func GetRepoSecuritySettings(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataRepos,
		mcp.Tool{
			Name:        "get_repo_security_settings",
			Description: t("TOOL_GET_REPO_SECURITY_SETTINGS_DESCRIPTION", "Get a repository's security configuration: visibility, security_and_analysis (advanced security, secret scanning, push protection, dependabot), and whether private vulnerability reporting is enabled."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_REPO_SECURITY_SETTINGS_USER_TITLE", "Get repository security settings"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner": {Type: "string", Description: "The owner of the repository."},
					"repo":  {Type: "string", Description: "The name of the repository."},
				},
				Required: []string{"owner", "repo"},
			},
		},
		[]scopes.Scope{scopes.Repo},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			repository, resp, err := client.Repositories.Get(ctx, owner, repo)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to get repository", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get repository", resp, body), nil, nil
			}

			// Second call: vulnerability alerts enabled is a separate endpoint.
			// 404 (no preview header / GHES without GHAS) is not fatal — report unknown.
			vaEnabled, vaResp, vaErr := client.Repositories.GetVulnerabilityAlerts(ctx, owner, repo)
			if vaResp != nil {
				defer func() { _ = vaResp.Body.Close() }()
			}

			out := map[string]any{
				"name":                                  repository.GetName(),
				"full_name":                             repository.GetFullName(),
				"private":                               repository.GetPrivate(),
				"visibility":                            repository.GetVisibility(),
				"archived":                              repository.GetArchived(),
				"disabled":                              repository.GetDisabled(),
				"default_branch":                        repository.GetDefaultBranch(),
				"security_and_analysis":                 repository.GetSecurityAndAnalysis(),
				"delete_branch_on_merge":                repository.GetDeleteBranchOnMerge(),
				"web_commit_signoff_required":           repository.GetWebCommitSignoffRequired(),
				"secret_scanning_push_protection_state": secretScanningPushProtectionState(repository),
			}
			if vaErr == nil {
				out["vulnerability_alerts_enabled"] = vaEnabled
			}

			r, err := json.Marshal(out)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal repository security settings", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// secretScanningPushProtectionState returns "enabled", "disabled", or "" when unknown.
// Avoids forcing the AI to interpret nil pointers in the security_and_analysis block.
func secretScanningPushProtectionState(r *github.Repository) string {
	sa := r.GetSecurityAndAnalysis()
	if sa == nil {
		return ""
	}
	pp := sa.GetSecretScanningPushProtection()
	if pp == nil {
		return ""
	}
	return pp.GetStatus()
}

// GetBranchProtection returns the classic branch-protection ruleset for a single branch.
// For modern protection, prefer list_repo_rulesets / get_repo_ruleset.
func GetBranchProtection(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataRepos,
		mcp.Tool{
			Name:        "get_branch_protection",
			Description: t("TOOL_GET_BRANCH_PROTECTION_DESCRIPTION", "Get the classic branch protection rules applied to a specific branch (required reviews, status checks, signed commits, force-push restrictions, etc.)."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_BRANCH_PROTECTION_USER_TITLE", "Get branch protection"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner":  {Type: "string", Description: "The owner of the repository."},
					"repo":   {Type: "string", Description: "The name of the repository."},
					"branch": {Type: "string", Description: "The branch name (e.g. \"main\")."},
				},
				Required: []string{"owner", "repo", "branch"},
			},
		},
		[]scopes.Scope{scopes.Repo},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			branch, err := RequiredParam[string](args, "branch")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			protection, resp, err := client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to get branch protection", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get branch protection", resp, body), nil, nil
			}

			r, err := json.Marshal(protection)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal branch protection", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListRepoRulesets lists all rulesets configured on a repository, including those
// inherited from the parent organization or enterprise.
func ListRepoRulesets(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataRepos,
		mcp.Tool{
			Name:        "list_repo_rulesets",
			Description: t("TOOL_LIST_REPO_RULESETS_DESCRIPTION", "List all rulesets that apply to a repository (modern replacement for branch protection). Includes rulesets inherited from the org or enterprise."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_REPO_RULESETS_USER_TITLE", "List repository rulesets"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner":            {Type: "string", Description: "The owner of the repository."},
					"repo":             {Type: "string", Description: "The name of the repository."},
					"includes_parents": {Type: "boolean", Description: "Include rulesets inherited from the org/enterprise. Defaults to true."},
				},
				Required: []string{"owner", "repo"},
			}),
		},
		[]scopes.Scope{scopes.Repo},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			opts := &github.RepositoryListRulesetsOptions{
				ListOptions: github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage},
			}
			if v, ok := args["includes_parents"].(bool); ok {
				opts.IncludesParents = &v
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			rulesets, resp, err := client.Repositories.GetAllRulesets(ctx, owner, repo, opts)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list rulesets", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list rulesets", resp, body), nil, nil
			}

			r, err := json.Marshal(rulesets)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal rulesets", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// GetRepoRuleset fetches a single ruleset by ID, including its full rule list and
// inherited-from-parent flag (if applicable).
func GetRepoRuleset(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataRepos,
		mcp.Tool{
			Name:        "get_repo_ruleset",
			Description: t("TOOL_GET_REPO_RULESET_DESCRIPTION", "Get a single repository ruleset by ID, including its rules and conditions."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_REPO_RULESET_USER_TITLE", "Get repository ruleset"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner":            {Type: "string", Description: "The owner of the repository."},
					"repo":             {Type: "string", Description: "The name of the repository."},
					"ruleset_id":       {Type: "number", Description: "The ID of the ruleset (from list_repo_rulesets)."},
					"includes_parents": {Type: "boolean", Description: "Include parent (org/enterprise) ruleset details. Defaults to true."},
				},
				Required: []string{"owner", "repo", "ruleset_id"},
			},
		},
		[]scopes.Scope{scopes.Repo},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			id, err := RequiredInt(args, "ruleset_id")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			includesParents := true
			if v, ok := args["includes_parents"].(bool); ok {
				includesParents = v
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			ruleset, resp, err := client.Repositories.GetRuleset(ctx, owner, repo, int64(id), includesParents)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to get ruleset", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get ruleset", resp, body), nil, nil
			}

			r, err := json.Marshal(ruleset)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal ruleset", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// GetCodeownersErrors returns the list of CODEOWNERS file syntax/path errors for a repo.
// Useful for validating that the file actually maps owners as intended.
func GetCodeownersErrors(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataRepos,
		mcp.Tool{
			Name:        "get_codeowners_errors",
			Description: t("TOOL_GET_CODEOWNERS_ERRORS_DESCRIPTION", "List syntax errors in a repository's CODEOWNERS file (parse failures, missing usernames/teams, invalid paths). An empty errors list means CODEOWNERS is well-formed."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_CODEOWNERS_ERRORS_USER_TITLE", "Get CODEOWNERS errors"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner": {Type: "string", Description: "The owner of the repository."},
					"repo":  {Type: "string", Description: "The name of the repository."},
					"ref":   {Type: "string", Description: "Optional. A branch, tag, or SHA. Defaults to the default branch."},
				},
				Required: []string{"owner", "repo"},
			},
		},
		[]scopes.Scope{scopes.Repo},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			ref, err := OptionalParam[string](args, "ref")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			var opts *github.GetCodeownersErrorsOptions
			if ref != "" {
				opts = &github.GetCodeownersErrorsOptions{Ref: ref}
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			errors, resp, err := client.Repositories.GetCodeownersErrors(ctx, owner, repo, opts)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to get CODEOWNERS errors", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get CODEOWNERS errors", resp, body), nil, nil
			}

			r, err := json.Marshal(errors)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal CODEOWNERS errors", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}
