import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { env } from '../config.js';
import { snykGet } from '../snyk/client.js';
import type {
  CoordinateSummary,
  IssueSummary,
  SnykItem,
} from '../utils/helpers.js';
import {
  looksLikeUuid,
  normalizeVersion,
  requireRestIssueUuid,
} from '../utils/helpers.js';

// ---------------------------------------------------------------------------
// Shared helpers for the issues domain
// ---------------------------------------------------------------------------

export function summarizeIssueV3(item: SnykItem): IssueSummary {
  const attrs: Record<string, unknown> = item?.attributes ?? {};

  const coordinates = Array.isArray(attrs.coordinates)
    ? (attrs.coordinates as Record<string, unknown>[]).map(
        (c: Record<string, unknown>) => {
          const reps = Array.isArray(c.representations)
            ? (c.representations as Record<string, unknown>[]).map(
                (r: Record<string, unknown>) => {
                  const loc = r?.sourceLocation as
                    Record<string, unknown> | undefined;
                  return {
                    id: r?.id as string | undefined,
                    type: r?.type as string | undefined,
                    identity: r?.identity as string | undefined,
                    packageName: (r?.package_name ?? r?.packageName) as
                      string | undefined,
                    packageVersion: normalizeVersion(
                      r?.package_version ?? r?.packageVersion,
                    ),
                    purl: r?.purl as string | undefined,
                    file: loc?.file as string | undefined,
                    commitId: loc?.commit_id as string | undefined,
                    region: loc?.region as string | undefined,
                  };
                },
              )
            : [];
          const remedies = Array.isArray(c.remedies)
            ? c.remedies.map((r: Record<string, unknown>) => {
                const details =
                  typeof r?.details === 'object' && r?.details !== null
                    ? (r.details as Record<string, unknown>)
                    : {};
                return {
                  id: r?.id,
                  type: r?.type,
                  description: r?.description,
                  details: {
                    ...details,
                    upgradePackage:
                      (details['upgrade_package'] as
                        string | null | undefined) ??
                      (details['upgradePackage'] as
                        string | null | undefined) ??
                      null,
                  },
                };
              })
            : [];
          return {
            state: c.state,
            createdAt: c.created_at,
            resolvedAt: c.last_resolved_at,
            isFixableManually: c.is_fixable_manually,
            isFixableSnyk: c.is_fixable_snyk,
            isFixableUpstream: c.is_fixable_upstream,
            remedies,
            representations: reps,
          };
        },
      )
    : [];

  const risk = (attrs.risk ?? {}) as Record<string, unknown>;
  const classes = Array.isArray(attrs.classes)
    ? (attrs.classes as Record<string, unknown>[]).map(
        (c: Record<string, unknown>) => ({
          id: c.id as string | undefined,
          type: c.type as string | undefined,
          source: c.source as string | undefined,
        }),
      )
    : [];
  const problems = Array.isArray(attrs.problems)
    ? (attrs.problems as Record<string, unknown>[]).map(
        (p: Record<string, unknown>) => ({
          id: p.id as string | undefined,
          type: p.type as string | undefined,
          source: p.source as string | undefined,
        }),
      )
    : [];

  return {
    id: item?.id,
    key: attrs.key as string | undefined,
    title: attrs.title as string | undefined,
    description: attrs.description as string | undefined,
    type: attrs.type as string | undefined,
    effectiveSeverityLevel: attrs.effective_severity_level as
      string | undefined,
    status: attrs.status as string | undefined,
    ignored: attrs.ignored as boolean | undefined,
    createdAt: attrs.created_at as string | undefined,
    updatedAt: attrs.updated_at as string | undefined,
    classes,
    problems,
    coordinates: coordinates as CoordinateSummary[],
    risk: {
      score: (risk['score'] as Record<string, unknown> | undefined)?.value,
      model: (risk['score'] as Record<string, unknown> | undefined)?.model,
      factors: risk['factors'],
    },
    resolution: attrs.resolution,
    scanItemId: item?.relationships?.scan_item?.data?.id,
    organizationId: item?.relationships?.organization?.data?.id,
  };
}

export async function resolveProjectIssueIds(
  orgId: string,
  projectId: string,
  issueId: string,
  apiVersion: string,
) {
  let restIssue: IssueSummary | null;
  let v1IssueId = issueId;

  if (looksLikeUuid(issueId)) {
    const detail = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues/${encodeURIComponent(issueId)}?version=${encodeURIComponent(apiVersion)}`,
    );
    restIssue = detail?.data ? summarizeIssueV3(detail.data) : null;
    v1IssueId = restIssue?.key ?? issueId;
  } else {
    const params = new URLSearchParams({
      version: apiVersion,
      limit: '100',
      'scan_item.type': 'project',
      'scan_item.id': projectId,
    });
    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
    );
    const items = Array.isArray(data?.data) ? data.data : [];
    const match = items.find(
      (item: SnykItem) => item?.attributes?.key === issueId,
    );
    restIssue = match ? summarizeIssueV3(match) : null;
  }

  return {
    restIssue,
    restIssueId: restIssue?.id ?? (looksLikeUuid(issueId) ? issueId : null),
    v1IssueId,
  };
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerIssueTools(server: McpServer) {
  // -----------------------------------------------------------------------
  // snyk_get_project_issues
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_project_issues',
    {
      description:
        'List all Snyk issues for a specific project (by project ID). ' +
        "Supports filtering by type ('code' or 'package'), severity, and status. " +
        'Use snyk_get_targets and snyk_get_projects first to find the project ID for a given repository.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        projectId: z
          .string()
          .describe(
            'Snyk project ID (UUID). Use snyk_get_targets to discover project IDs for a target.',
          ),
        issueType: z
          .enum(['code', 'package', 'all'])
          .optional()
          .default('all')
          .describe(
            "Filter by issue type: 'code' (Snyk Code), 'package' (open source), or 'all'.",
          ),
        severity: z
          .enum(['low', 'medium', 'high', 'critical'])
          .optional()
          .describe('Filter by effective severity level.'),
        status: z
          .enum(['open', 'resolved', 'ignored'])
          .optional()
          .describe('Filter by issue status.'),
        limit: z
          .number()
          .optional()
          .default(100)
          .describe('Max results to return (1-100).'),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({
      orgId,
      projectId,
      issueType,
      severity,
      status,
      limit,
      version,
    }) => {
      const apiVersion = version || env.SNYK_API_VERSION;
      const API_PAGE_SIZE = 100;

      const params = new URLSearchParams({
        version: apiVersion,
        limit: String(API_PAGE_SIZE),
        'scan_item.type': 'project',
        'scan_item.id': projectId,
      });

      let snykType: string | undefined;
      if (issueType === 'code') snykType = 'code';
      else if (issueType === 'package') snykType = 'package';

      if (snykType) params.set('type', snykType);
      if (severity) params.set('effective_severity_level', severity);
      if (status) params.set('status', status);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
      );

      let items = Array.isArray(data?.data) ? data.data : [];
      items = items.slice(0, limit);

      const result = {
        query: {
          orgId,
          projectId,
          issueType,
          severity,
          status,
          limit,
          apiVersion,
        },
        matchCount: items.length,
        issues: items.map(summarizeIssueV3),
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // -----------------------------------------------------------------------
  // snyk_list_org_issues
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_list_org_issues',
    {
      description:
        "List issues for a Snyk organization. Supports filtering by type ('code' or 'package'), " +
        'severity, status, and free-text title search. Use this to find Snyk Code issues (type=code) ' +
        "or to discover issues when you only have a title keyword (e.g. 'Hardcoded Secret').",
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        issueType: z
          .enum(['code', 'package', 'all'])
          .optional()
          .default('all')
          .describe(
            "Filter by issue type: 'code' (Snyk Code), 'package' (open source), or 'all'.",
          ),
        severity: z
          .enum(['low', 'medium', 'high', 'critical'])
          .optional()
          .describe('Filter by effective severity level.'),
        status: z
          .enum(['open', 'resolved', 'ignored'])
          .optional()
          .describe('Filter by issue status.'),
        titleSearch: z
          .string()
          .optional()
          .describe(
            'Free-text search on issue title (client-side substring match). Case-insensitive.',
          ),
        limit: z
          .number()
          .optional()
          .default(100)
          .describe('Max results to return (1-100).'),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({
      orgId,
      issueType,
      severity,
      status,
      titleSearch,
      limit,
      version,
    }) => {
      const apiVersion = version || env.SNYK_API_VERSION;

      const API_PAGE_SIZE = 100;

      const params = new URLSearchParams({
        version: apiVersion,
        limit: String(API_PAGE_SIZE),
      });

      let snykType: string | undefined;
      if (issueType === 'code') snykType = 'code';
      else if (issueType === 'package') snykType = 'package';

      if (snykType) params.set('type', snykType);
      if (severity) params.set('effective_severity_level', severity);
      if (status) params.set('status', status);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
      );

      let items = Array.isArray(data?.data) ? data.data : [];

      if (titleSearch) {
        const lower = titleSearch.toLowerCase();
        items = items.filter((item: SnykItem) => {
          const title = (item?.attributes?.title as string) ?? '';
          const description = (item?.attributes?.description as string) ?? '';
          return (
            title.toLowerCase().includes(lower) ||
            description.toLowerCase().includes(lower)
          );
        });
      }

      items = items.slice(0, limit);

      const result = {
        query: {
          orgId,
          issueType,
          severity,
          status,
          titleSearch,
          limit,
          apiVersion,
        },
        matchCount: items.length,
        issues: items.map(summarizeIssueV3),
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // -----------------------------------------------------------------------
  // snyk_get_issue_detail
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_issue_detail',
    {
      description:
        'Get full details of a single Snyk issue by its REST API issue ID ' +
        "(e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'). " +
        'Use snyk_list_org_issues first to discover the issue ID from a title keyword. ' +
        "NOTE: The fragment ID from a Snyk web UI URL (like '#issue-2f30d999-...') is NOT " +
        'a REST API issue ID — you must find the real ID via snyk_list_org_issues.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        issueId: z
          .string()
          .describe(
            "Snyk REST API issue ID (UUID), e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'. " +
              'NOT the fragment from a web UI URL.',
          ),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({ orgId, issueId, version }) => {
      const apiVersion = version || env.SNYK_API_VERSION;

      requireRestIssueUuid('snyk_get_issue_detail', issueId);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/issues/${encodeURIComponent(issueId)}?version=${encodeURIComponent(apiVersion)}`,
      );

      const result = {
        query: { orgId, issueId, apiVersion },
        issue: data?.data ? summarizeIssueV3(data.data) : null,
        raw: data,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
