import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { serverVersion } from '../version.js';

export function registerOnboardingTool(server: McpServer) {
  server.registerTool(
    'snyk_onboarding',
    {
      description:
        'Get an overview of all available Snyk tools, their recommended workflow, ' +
        'and best practices. Call this first when onboarding to understand how to use the server.',
      inputSchema: {},
    },
    async () => {
      const guide = {
        server: `snyk-api-mcp v${serverVersion}`,
        description:
          'Snyk REST + V1 API bridge — use REST for discovery/detail flows and V1 where project-path analysis is still stronger.',
        identifierRules: {
          orgId:
            'Always the Snyk organization UUID, never an org display name or slug.',
          orgSlug:
            'When using snyk_resolve_org_id, pass the exact organization slug.',
          projectId:
            'Always the Snyk project UUID, never a project name, repo name, or display name.',
          restIssueId:
            'Always the REST issue resource UUID returned by snyk_get_project_issues, snyk_list_org_issues, or snyk_get_issue_detail.',
          vulnerabilityId:
            'A Snyk vulnerability identifier like SNYK-JAVA-..., typically returned by package vulnerability lookups.',
          issueKey:
            'Opaque bridge identifier used internally to connect REST issue resources to legacy V1 project-path endpoints.',
        },
        recommendedWorkflow: [
          {
            step: 1,
            tool: 'snyk_resolve_org_id',
            input: "exact orgSlug (e.g. 'my-snyk-org')",
            output: 'orgId (UUID)',
            note: 'You can also use the org UUID directly if you already know it.',
          },
          {
            step: 2,
            tool: 'snyk_get_targets',
            input: "orgId, optional displayName (e.g. 'my-org/my-repo')",
            output: 'target(s) with id, url, origin',
            note: 'A target is a GitHub repo, container image, etc. orgId must be the org UUID.',
          },
          {
            step: 3,
            tool: 'snyk_get_target_ledger_seed',
            input: 'orgId, targetId',
            output:
              'issues-ledger seed with flat issues[] and grouped advisories[]',
            note: 'Canonical target-scoped intake for session-init and remediation loops. Contract is fixed to open package_vulnerability + code issues.',
          },
          {
            step: 4,
            tool: 'snyk_get_projects',
            input: 'orgId, optional targetId',
            output:
              'projects with id, name, type (pnpm/dockerfile/sast), status',
            note: 'A target can have multiple projects (e.g. each package.json is a separate pnpm project). Use the returned project id as projectId in later calls.',
          },
          {
            step: 5,
            tool: 'snyk_get_project_ledger_seed',
            input: 'orgId, projectId',
            output:
              'issues-ledger seed with flat issues[] and grouped advisories[] for one project',
            note: 'Canonical project-scoped intake for session-init when you want to remediate exactly one project instead of all projects under a target.',
          },
          {
            step: 6,
            tool: 'snyk_get_project_issues',
            input: 'orgId, projectId, optional severity/status/issueType/limit',
            output:
              'issues list with restIssueId, issueKey, title, risk score, and status',
            note: "Use issueType='package_vulnerability' or issueType='code' plus severity='critical' and status='open' to focus the result set. projectId must be the Snyk project UUID returned by snyk_get_projects.",
          },
        ],
        additionalTools: [
          {
            tool: 'snyk_list_org_issues',
            description:
              'List issues across the entire org using explicit API filters.',
          },
          {
            tool: 'snyk_get_issue_detail',
            description:
              'Get full detail for a single issue (by REST API UUID, not the web UI fragment ID).',
          },
          {
            tool: 'snyk_get_package_issue_description',
            description:
              'Look up direct package vulnerabilities by exact PURL (e.g. pkg:npm/axios@1.7.0) and receive vulnerabilityId values.',
          },
          {
            tool: 'snyk_get_project_package_vulnerability_analysis',
            description:
              'Get package_vulnerability-specific project analysis for an exact REST issue UUID and exact package PURL.',
          },
          {
            tool: 'snyk_get_project_issue_paths',
            description:
              'Get dependency path details for a project issue by REST issue UUID.',
          },
        ],
        tips: [
          'Always resolve the org ID first — most tools require it.',
          'When a tool asks for orgId or projectId, pass the Snyk UUID returned by earlier tools, not a display name.',
          'Strict input contracts apply: pass exact slugs, exact restIssueId UUIDs, exact PURLs, and treat issueKey as an internal bridge identifier rather than a user-facing primary ID.',
          "Use canonical Snyk issueType values in public contracts: 'package_vulnerability' and 'code'.",
          'Discovery, listing, and issue-detail flows use the Snyk REST API; dependency-path analysis resolves the REST issue UUID to a legacy V1 issue key internally.',
          'For session initialization, choose the seed scope explicitly: target-wide via snyk_get_target_ledger_seed or single-project via snyk_get_project_ledger_seed.',
          "Filter issues by severity+status to reduce noise (e.g. severity='critical', status='open').",
          "The same vulnerability (same Snyk key) may appear in multiple projects — that's expected.",
          'Use snyk_get_projects with targetId to efficiently list all projects for one repo.',
        ],
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(guide, null, 2) }],
      };
    },
  );
}
