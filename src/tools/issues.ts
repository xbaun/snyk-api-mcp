import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import {
  resolveRestApiVersion,
  type SnykIssueTypeFilter,
  snykRestApi,
  type SnykScanItemType,
  type SnykSeverityFilter,
  type SnykStatusFilter,
} from '../snyk/client.js';
import type { operations } from '../snyk/types/snyk-rest.d.ts';
import type {
  CoordinateSummary,
  PackageVulnerabilitySummary,
  RestIssueSummary,
  SnykItem,
} from '../utils/helpers.js';
import { normalizeVersion, requireRestIssueUuid } from '../utils/helpers.js';

// ---------------------------------------------------------------------------
// Shared helpers for the issues domain
// ---------------------------------------------------------------------------

function summarizeIssueLike(item: SnykItem) {
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
                    region: loc?.region as Record<string, unknown> | undefined,
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
    issueKey: attrs.key as string | undefined,
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
  };
}

export function summarizeRestIssue(item: SnykItem): RestIssueSummary {
  const scanItemRelationship = item?.relationships?.scan_item?.data;
  const organizationRelationship = item?.relationships?.organization?.data;

  return {
    restIssueId: item?.id ?? '',
    ...summarizeIssueLike(item),
    scanItemId: Array.isArray(scanItemRelationship)
      ? (scanItemRelationship[0]?.id ?? undefined)
      : (scanItemRelationship?.id ?? undefined),
    organizationId: Array.isArray(organizationRelationship)
      ? (organizationRelationship[0]?.id ?? undefined)
      : (organizationRelationship?.id ?? undefined),
  };
}

export function summarizePackageVulnerability(
  item: SnykItem,
): PackageVulnerabilitySummary {
  return {
    vulnerabilityId: item?.id ?? '',
    ...summarizeIssueLike(item),
  };
}

type IssueTypeInput = 'code' | 'package' | 'all';
type IssueStatusInput = 'open' | 'resolved' | 'ignored';
type IssueSeverityInput = 'low' | 'medium' | 'high' | 'critical';
type ListIssuesQuery = operations['listOrgIssues']['parameters']['query'];

function mapIssueTypeToRest(issueType: IssueTypeInput) {
  if (issueType === 'code') return 'code';
  if (issueType === 'package') return 'package_vulnerability';
  return undefined;
}

function buildListIssuesQuery({
  apiVersion,
  issueType,
  severity,
  status,
  scanItemId,
  scanItemType,
}: {
  apiVersion: string;
  issueType: IssueTypeInput;
  severity?: IssueSeverityInput;
  status?: IssueStatusInput;
  scanItemId?: string;
  scanItemType?: SnykScanItemType;
}): ListIssuesQuery {
  const query: ListIssuesQuery = {
    version: apiVersion,
    limit: 100,
  };

  const restIssueType = mapIssueTypeToRest(issueType);
  if (restIssueType) {
    query.type = restIssueType as SnykIssueTypeFilter;
  }

  if (severity) {
    query.effective_severity_level = [severity] as SnykSeverityFilter[];
  }

  if (status === 'ignored') {
    query.ignored = true;
  } else if (status) {
    query.status = [status] as SnykStatusFilter[];
  }

  if (scanItemId) {
    query['scan_item.id'] = scanItemId;
  }

  if (scanItemType) {
    query['scan_item.type'] = scanItemType;
  }

  return query;
}
export async function resolveIssueKeyFromRestId(
  orgId: string,
  restIssueId: string,
  apiVersion: string,
) {
  requireRestIssueUuid('resolveIssueKeyFromRestId', restIssueId);

  const detail = snykRestApi.expectData(
    await snykRestApi.client.GET('/orgs/{org_id}/issues/{issue_id}', {
      params: {
        path: { org_id: orgId, issue_id: restIssueId },
        query: { version: apiVersion },
      },
    }),
  );

  if (!detail?.data) {
    throw new Error(
      `Snyk REST issue '${restIssueId}' returned no issue resource.`,
    );
  }

  const restIssue = summarizeRestIssue(detail.data);
  const issueKey = restIssue.issueKey;

  if (!issueKey) {
    throw new Error(
      `Snyk REST issue '${restIssueId}' did not include an issue key required for dependency path queries.`,
    );
  }

  return {
    restIssue,
    issueKey,
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
      },
    },
    async ({ orgId, projectId, issueType, severity, status, limit }) => {
      const apiVersion = resolveRestApiVersion();
      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/issues', {
          params: {
            path: { org_id: orgId },
            query: buildListIssuesQuery({
              apiVersion,
              issueType,
              severity,
              status,
              scanItemId: projectId,
              scanItemType: 'project',
            }),
          },
        }),
      );

      const items = (Array.isArray(data?.data) ? data.data : []).slice(
        0,
        limit,
      );

      const result = {
        query: {
          orgId,
          projectId,
          issueType,
          severity,
          status,
          limit,
        },
        matchCount: items.length,
        issues: items.map(summarizeRestIssue),
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
        'severity, and status.',
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
        limit: z
          .number()
          .optional()
          .default(100)
          .describe('Max results to return (1-100).'),
      },
    },
    async ({ orgId, issueType, severity, status, limit }) => {
      const apiVersion = resolveRestApiVersion();
      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/issues', {
          params: {
            path: { org_id: orgId },
            query: buildListIssuesQuery({
              apiVersion,
              issueType,
              severity,
              status,
            }),
          },
        }),
      );

      const items = (Array.isArray(data?.data) ? data.data : []).slice(
        0,
        limit,
      );

      const result = {
        query: {
          orgId,
          issueType,
          severity,
          status,
          limit,
        },
        matchCount: items.length,
        issues: items.map(summarizeRestIssue),
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
        'Get full details of a single Snyk issue by its REST issue resource ID ' +
        "(e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'). " +
        'Use snyk_list_org_issues or snyk_get_project_issues first to discover the restIssueId. ' +
        "NOTE: The fragment ID from a Snyk web UI URL (like '#issue-2f30d999-...') is NOT " +
        'a restIssueId — you must find the real ID via one of the issue listing tools.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        restIssueId: z
          .string()
          .describe(
            "Snyk REST issue resource ID (UUID), e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'. " +
              'NOT the fragment from a web UI URL.',
          ),
      },
    },
    async ({ orgId, restIssueId }) => {
      const apiVersion = resolveRestApiVersion();

      requireRestIssueUuid('snyk_get_issue_detail', restIssueId);

      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/issues/{issue_id}', {
          params: {
            path: { org_id: orgId, issue_id: restIssueId },
            query: { version: apiVersion },
          },
        }),
      );

      const result = {
        query: { orgId, restIssueId },
        issue: data?.data ? summarizeRestIssue(data.data) : null,
        raw: data,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
