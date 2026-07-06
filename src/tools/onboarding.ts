import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

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
        server: 'snyk-api-mcp v0.2.0',
        description:
          'Snyk REST API bridge — find repositories, projects, and security vulnerabilities.',
        identifierRules: {
          orgId:
            'Always the Snyk organization UUID, never an org display name or slug.',
          projectId:
            'Always the Snyk project UUID, never a project name, repo name, or display name.',
        },
        recommendedWorkflow: [
          {
            step: 1,
            tool: 'snyk_resolve_org_id',
            input: "orgSlug (e.g. 'my-snyk-org')",
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
            tool: 'snyk_get_projects',
            input: 'orgId, optional targetId',
            output:
              'projects with id, name, type (pnpm/dockerfile/sast), status',
            note: 'A target can have multiple projects (e.g. each package.json is a separate pnpm project). Use the returned project id as projectId in later calls.',
          },
          {
            step: 4,
            tool: 'snyk_get_project_issues',
            input: 'orgId, projectId, optional severity/status/issueType/limit',
            output: 'issues list with id, title, CVE, risk score, status',
            note: "Use severity='critical' and status='open' to find the most urgent issues. projectId must be the Snyk project UUID returned by snyk_get_projects.",
          },
        ],
        additionalTools: [
          {
            tool: 'snyk_list_org_issues',
            description:
              'Search all issues across the entire org. Supports titleSearch for keyword matching.',
          },
          {
            tool: 'snyk_get_issue_detail',
            description:
              'Get full detail for a single issue (by REST API UUID, not the web UI fragment ID).',
          },
          {
            tool: 'snyk_get_package_issue_description',
            description:
              'Look up all known vulnerabilities for a package by PURL (e.g. pkg:npm/axios@1.7.0).',
          },
          {
            tool: 'snyk_get_project_issue_paths',
            description:
              'Get the data flow path for a vulnerability in a project (v1 API).',
          },
        ],
        tips: [
          'Always resolve the org ID first — most tools require it.',
          'When a tool asks for orgId or projectId, pass the Snyk UUID returned by earlier tools, not a display name.',
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
