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

// GetOrgSecuritySettings returns security-relevant fields from the organization profile —
// MFA enforcement, default repository permissions, member-creation rules, and the
// org-wide defaults for advanced security / dependabot / secret scanning.
// Avoids exposing the full noisy `get_org` payload for posture-only investigations.
func GetOrgSecuritySettings(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "get_org_security_settings",
			Description: t("TOOL_GET_ORG_SECURITY_SETTINGS_DESCRIPTION", "Get an organization's security and access defaults: MFA enforcement, default repository permissions, member capabilities, and org-wide defaults for advanced security, secret scanning, and Dependabot."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_ORG_SECURITY_SETTINGS_USER_TITLE", "Get organization security settings"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
				},
				Required: []string{"org"},
			},
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			organization, resp, err := client.Organizations.Get(ctx, org)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to get organization", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get organization", resp, body), nil, nil
			}

			out := map[string]any{
				"login":                                              organization.GetLogin(),
				"two_factor_requirement_enabled":                     organization.GetTwoFactorRequirementEnabled(),
				"default_repository_permission":                      organization.GetDefaultRepoPermission(),
				"members_can_create_repositories":                    organization.GetMembersCanCreateRepos(),
				"members_can_create_public_repositories":             organization.GetMembersCanCreatePublicRepos(),
				"members_can_create_private_repositories":            organization.GetMembersCanCreatePrivateRepos(),
				"members_can_create_internal_repositories":           organization.GetMembersCanCreateInternalRepos(),
				"members_can_fork_private_repositories":              organization.GetMembersCanForkPrivateRepos(),
				"members_allowed_repository_creation_type":           organization.GetMembersAllowedRepositoryCreationType(),
				"members_can_delete_repositories":                    organization.GetMembersCanDeleteRepositories(),
				"members_can_change_repo_visibility":                 organization.GetMembersCanChangeRepoVisibility(),
				"members_can_invite_outside_collaborators":           organization.GetMembersCanInviteOutsideCollaborators(),
				"members_can_create_teams":                           organization.GetMembersCanCreateTeams(),
				"web_commit_signoff_required":                        organization.GetWebCommitSignoffRequired(),
				"advanced_security_enabled_for_new_repositories":     organization.GetAdvancedSecurityEnabledForNewRepos(),
				"dependabot_alerts_enabled_for_new_repositories":     organization.GetDependabotAlertsEnabledForNewRepos(),
				"dependabot_security_updates_enabled_for_new_repos":  organization.GetDependabotSecurityUpdatesEnabledForNewRepos(),
				"secret_scanning_enabled_for_new_repositories":       organization.GetSecretScanningEnabledForNewRepos(),
				"secret_scanning_push_protection_enabled_for_new":    organization.GetSecretScanningPushProtectionEnabledForNewRepos(),
				"secret_scanning_validity_checks_enabled":            organization.GetSecretScanningValidityChecksEnabled(),
			}

			r, err := json.Marshal(out)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal organization security settings", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// listOrgMembersFiltered is the shared handler for list_org_admins and
// list_org_members_2fa_disabled — both back onto Organizations.ListMembers with
// different option fields. Splitting into two tools makes AI selection deterministic.
func listOrgMembersFiltered(role, filter, errCtx string) func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		org, err := RequiredParam[string](args, "org")
		if err != nil {
			return utils.NewToolResultError(err.Error()), nil, nil
		}
		pagination, err := OptionalPaginationParams(args)
		if err != nil {
			return utils.NewToolResultError(err.Error()), nil, nil
		}
		opts := &github.ListMembersOptions{
			Filter:      filter,
			Role:        role,
			ListOptions: github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage},
		}

		client, err := deps.GetClient(ctx)
		if err != nil {
			return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
		}

		members, resp, err := client.Organizations.ListMembers(ctx, org, opts)
		if err != nil {
			return ghErrors.NewGitHubAPIErrorResponse(ctx, errCtx, resp, err), nil, nil
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
			}
			return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, errCtx, resp, body), nil, nil
		}

		r, err := json.Marshal(members)
		if err != nil {
			return utils.NewToolResultErrorFromErr("failed to marshal members", err), nil, nil
		}
		return utils.NewToolResultText(string(r)), nil, nil
	}
}

// ListOrgAdmins lists organization owners (role=admin members).
func ListOrgAdmins(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_org_admins",
			Description: t("TOOL_LIST_ORG_ADMINS_DESCRIPTION", "List organization owners (members with admin role). Use this to audit who has full administrative access to the org."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_ADMINS_USER_TITLE", "List organization admins"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.ReadOrg},
		listOrgMembersFiltered("admin", "all", "failed to list org admins"),
	)
}

// ListOutsideCollaborators returns users who collaborate on org repos but are not org members.
func ListOutsideCollaborators(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_outside_collaborators",
			Description: t("TOOL_LIST_OUTSIDE_COLLABORATORS_DESCRIPTION", "List outside collaborators — users who have access to org repositories but are not members of the organization."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_OUTSIDE_COLLABORATORS_USER_TITLE", "List outside collaborators"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
					"filter": {
						Type:        "string",
						Description: "Filter outside collaborators. Possible values: \"2fa_disabled\", \"all\". Default \"all\".",
						Enum:        []any{"2fa_disabled", "all"},
					},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			filter, err := OptionalParam[string](args, "filter")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			opts := &github.ListOutsideCollaboratorsOptions{
				Filter:      filter,
				ListOptions: github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage},
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			users, resp, err := client.Organizations.ListOutsideCollaborators(ctx, org, opts)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list outside collaborators", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list outside collaborators", resp, body), nil, nil
			}

			r, err := json.Marshal(users)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal outside collaborators", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListOrgInstallations lists GitHub Apps installed on an organization — the third-party
// access surface for posture audits.
func ListOrgInstallations(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_org_installations",
			Description: t("TOOL_LIST_ORG_INSTALLATIONS_DESCRIPTION", "List GitHub Apps installed on an organization. Use this to audit third-party app access (each installation has its own permission set)."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_INSTALLATIONS_USER_TITLE", "List org App installations"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			installs, resp, err := client.Organizations.ListInstallations(ctx, org, &github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage})
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list installations", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list installations", resp, body), nil, nil
			}

			r, err := json.Marshal(installs)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal installations", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListSecurityManagers returns the team(s) granted security manager privileges.
func ListSecurityManagers(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_security_managers",
			Description: t("TOOL_LIST_SECURITY_MANAGERS_DESCRIPTION", "List teams granted security manager role on the organization. These teams can manage security alerts and policies across all org repos."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_SECURITY_MANAGERS_USER_TITLE", "List security managers"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
				},
				Required: []string{"org"},
			},
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			teams, resp, err := client.Organizations.ListSecurityManagerTeams(ctx, org)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list security manager teams", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list security manager teams", resp, body), nil, nil
			}

			r, err := json.Marshal(teams)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal security manager teams", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListOrgTeams enumerates teams in an organization.
func ListOrgTeams(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_org_teams",
			Description: t("TOOL_LIST_ORG_TEAMS_DESCRIPTION", "List teams in an organization. Use this to audit team-based access patterns."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_TEAMS_USER_TITLE", "List organization teams"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org": {Type: "string", Description: "The organization name."},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			teams, resp, err := client.Teams.ListTeams(ctx, org, &github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage})
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list teams", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list teams", resp, body), nil, nil
			}

			r, err := json.Marshal(teams)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal teams", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListOrgCodeSecurityConfigs lists central code-security configurations for an org.
// Available on Cloud and GHES 3.13+.
func ListOrgCodeSecurityConfigs(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataOrgs,
		mcp.Tool{
			Name:        "list_org_code_security_configs",
			Description: t("TOOL_LIST_ORG_CODE_SECURITY_CONFIGS_DESCRIPTION", "List the organization's code security configurations (central security baseline that can be applied to repos). Available on GHES 3.13+ and GitHub Cloud."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_CODE_SECURITY_CONFIGS_USER_TITLE", "List org code-security configurations"),
				ReadOnlyHint: true,
			},
			InputSchema: WithCursorPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org":         {Type: "string", Description: "The organization name."},
					"target_type": {Type: "string", Description: "Target type. Possible values: \"global\", \"all\". Default \"all\".", Enum: []any{"global", "all"}},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.ReadOrg},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalCursorPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			opts := &github.ListOrgCodeSecurityConfigurationOptions{}
			perPage := pagination.PerPage
			if perPage > 0 {
				opts.PerPage = &perPage
			}
			if pagination.After != "" {
				after := pagination.After
				opts.After = &after
			}
			if v, ok := args["target_type"].(string); ok && v != "" {
				opts.TargetType = &v
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			configs, resp, err := client.Organizations.ListCodeSecurityConfigurations(ctx, org, opts)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list code-security configurations", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list code-security configurations", resp, body), nil, nil
			}

			r, err := json.Marshal(configs)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal code-security configurations", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListOrgCodeScanningAlerts is the org-wide rollup; per-repo `list_code_scanning_alerts`
// already exists for single-repo investigation.
func ListOrgCodeScanningAlerts(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataCodeSecurity,
		mcp.Tool{
			Name:        "list_org_code_scanning_alerts",
			Description: t("TOOL_LIST_ORG_CODE_SCANNING_ALERTS_DESCRIPTION", "List code scanning alerts across all repositories in an organization."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_CODE_SCANNING_ALERTS_USER_TITLE", "List org code scanning alerts"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org":      {Type: "string", Description: "The organization name."},
					"state":    {Type: "string", Description: "Alert state. Default \"open\".", Enum: []any{"open", "closed", "dismissed", "fixed"}, Default: json.RawMessage(`"open"`)},
					"severity": {Type: "string", Description: "Filter by severity.", Enum: []any{"critical", "high", "medium", "low", "warning", "note", "error"}},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.SecurityEvents},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			state, err := OptionalParam[string](args, "state")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			severity, err := OptionalParam[string](args, "severity")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			alerts, resp, err := client.CodeScanning.ListAlertsForOrg(ctx, org, &github.AlertListOptions{
				State:       state,
				Severity:    severity,
				ListOptions: github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage},
			})
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list org code scanning alerts", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list org code scanning alerts", resp, body), nil, nil
			}

			r, err := json.Marshal(alerts)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal alerts", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}

// ListOrgSecretScanningAlerts is the org-wide rollup of secret scanning alerts.
func ListOrgSecretScanningAlerts(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataSecretProtection,
		mcp.Tool{
			Name:        "list_org_secret_scanning_alerts",
			Description: t("TOOL_LIST_ORG_SECRET_SCANNING_ALERTS_DESCRIPTION", "List secret scanning alerts across all repositories in an organization."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_ORG_SECRET_SCANNING_ALERTS_USER_TITLE", "List org secret scanning alerts"),
				ReadOnlyHint: true,
			},
			InputSchema: WithPagination(&jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"org":         {Type: "string", Description: "The organization name."},
					"state":       {Type: "string", Description: "Alert state.", Enum: []any{"open", "resolved"}},
					"secret_type": {Type: "string", Description: "Comma-separated list of secret types to return."},
					"resolution":  {Type: "string", Description: "Comma-separated list of resolutions. Valid: false_positive, wont_fix, revoked, pattern_edited, pattern_deleted, used_in_tests."},
				},
				Required: []string{"org"},
			}),
		},
		[]scopes.Scope{scopes.SecurityEvents},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			org, err := RequiredParam[string](args, "org")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			state, err := OptionalParam[string](args, "state")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			secretType, err := OptionalParam[string](args, "secret_type")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			resolution, err := OptionalParam[string](args, "resolution")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			pagination, err := OptionalPaginationParams(args)
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, nil
			}

			alerts, resp, err := client.SecretScanning.ListAlertsForOrg(ctx, org, &github.SecretScanningAlertListOptions{
				State:       state,
				SecretType:  secretType,
				Resolution:  resolution,
				ListOptions: github.ListOptions{Page: pagination.Page, PerPage: pagination.PerPage},
			})
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx, "failed to list org secret scanning alerts", resp, err), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, nil
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list org secret scanning alerts", resp, body), nil, nil
			}

			r, err := json.Marshal(alerts)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal alerts", err), nil, nil
			}
			return utils.NewToolResultText(string(r)), nil, nil
		},
	)
}
