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
import type { components, operations } from '../snyk/types/snyk-rest.d.ts';
import type {
  CoordinateSummary,
  PackageVulnerabilitySummary,
  RestIssueSummary,
} from '../utils/helpers.js';
import {
  normalizeVersion,
  parseUpgradePackageValue,
  requireRestIssueUuid,
  requireUuid,
} from '../utils/helpers.js';

type RestIssue = components['schemas']['Issue'];
type RestIssueAttributes = RestIssue['attributes'];
type RestIssueCoordinate = NonNullable<
  RestIssueAttributes['coordinates']
>[number];
type PackageIssue = components['schemas']['CommonIssueModelVThree'];
type PackageIssueAttributes = NonNullable<PackageIssue['attributes']>;
type PackageIssueCoordinate = NonNullable<
  PackageIssueAttributes['coordinates']
>[number];
type PackageIssueRepresentation =
  PackageIssueCoordinate['representations'][number];

// ---------------------------------------------------------------------------
// Shared helpers for the issues domain
// ---------------------------------------------------------------------------

function isPackageIssueRepresentation(
  representation: PackageIssueRepresentation,
): representation is Extract<
  PackageIssueRepresentation,
  { package?: unknown }
> {
  return 'package' in representation;
}

function summarizeRestCoordinate(
  coordinate: RestIssueCoordinate,
): CoordinateSummary {
  return {
    state: coordinate.state,
    createdAt: coordinate.created_at,
    resolvedAt: coordinate.last_resolved_at,
    isFixableManually: coordinate.is_fixable_manually,
    isFixableSnyk: coordinate.is_fixable_snyk,
    isFixableUpstream: coordinate.is_fixable_upstream,
    remedies: (coordinate.remedies ?? []).map((remedy) => {
      const fixedIn = parseUpgradePackageValue(remedy.meta?.data.fixed_in);
      return {
        type: remedy.type,
        description: remedy.description,
        details: {
          upgradePackage: fixedIn,
          fixedIn,
          schemaVersion: remedy.meta?.schema_version,
        },
      };
    }),
    representations: (coordinate.representations ?? []).map(
      (representation) => {
        if ('dependency' in representation) {
          return {
            packageName: representation.dependency.package_name,
            packageVersion: normalizeVersion(
              representation.dependency.package_version,
            ),
          };
        }

        if ('sourceLocation' in representation) {
          return {
            file: representation.sourceLocation.file,
            commitId: representation.sourceLocation.commit_id,
            region: representation.sourceLocation.region,
          };
        }

        if ('resourcePath' in representation) {
          return {
            resourcePath: representation.resourcePath,
          };
        }

        return {
          type: 'cloud_resource',
        };
      },
    ),
  };
}

function summarizePackageCoordinate(
  coordinate: PackageIssueCoordinate,
): CoordinateSummary {
  return {
    remedies: (coordinate.remedies ?? []).map((remedy) => ({
      type: remedy.type,
      description: remedy.description,
      details: {
        upgradePackage: parseUpgradePackageValue(
          remedy.details?.upgrade_package,
        ),
      },
    })),
    representations: coordinate.representations.map((representation) => {
      if (isPackageIssueRepresentation(representation)) {
        return {
          packageName: representation.package?.name,
          packageVersion: normalizeVersion(representation.package?.version),
          purl: representation.package?.url ?? null,
        };
      }

      return {
        resourcePath: representation.resource_path,
      };
    }),
  };
}

function summarizeRestIssueBase(attributes: RestIssueAttributes) {
  return {
    issueKey: attributes.key,
    title: attributes.title,
    description: attributes.description,
    type: attributes.type,
    effectiveSeverityLevel: attributes.effective_severity_level,
    status: attributes.status,
    ignored: attributes.ignored,
    createdAt: attributes.created_at,
    updatedAt: attributes.updated_at,
    classes: (attributes.classes ?? []).map((item) => ({
      id: item.id,
      type: item.type,
      source: item.source,
    })),
    problems: (attributes.problems ?? []).map((item) => ({
      id: item.id,
      type: item.type,
      source: item.source,
    })),
    coordinates: (attributes.coordinates ?? []).map(summarizeRestCoordinate),
    risk: {
      score: attributes.risk?.score?.value,
      model: attributes.risk?.score?.model,
      factors: attributes.risk?.factors,
      exploitMaturityLevels: attributes.exploit_details?.maturity_levels,
    },
    resolution: attributes.resolution,
  };
}

function summarizePackageIssueBase(attributes: PackageIssueAttributes) {
  return {
    title: attributes.title,
    description: attributes.description,
    type: attributes.type,
    effectiveSeverityLevel: attributes.effective_severity_level,
    createdAt: attributes.created_at,
    updatedAt: attributes.updated_at,
    classes: [],
    problems: (attributes.problems ?? []).map((item) => ({
      id: item.id,
      source: item.source,
    })),
    coordinates: (attributes.coordinates ?? []).map(summarizePackageCoordinate),
    risk: {},
  };
}

export function summarizeRestIssue(item: RestIssue): RestIssueSummary {
  const scanItemRelationship = item.relationships.scan_item.data;
  const organizationRelationship = item.relationships.organization.data;

  return {
    restIssueId: item.id,
    ...summarizeRestIssueBase(item.attributes),
    scanItemId: scanItemRelationship.id,
    organizationId: organizationRelationship.id,
  };
}

export function summarizePackageVulnerability(
  item: PackageIssue,
): PackageVulnerabilitySummary {
  const attributes = item.attributes ?? {};

  return {
    vulnerabilityId: item.id ?? '',
    ...summarizePackageIssueBase(attributes),
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
    query.type = restIssueType satisfies SnykIssueTypeFilter;
  }

  if (severity) {
    query.effective_severity_level = [severity] satisfies SnykSeverityFilter[];
  }

  if (status === 'ignored') {
    query.ignored = true;
  } else if (status === 'open' || status === 'resolved') {
    query.status = [status] satisfies SnykStatusFilter[];
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
      requireUuid('orgId', orgId);
      requireUuid('projectId', projectId);

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
      requireUuid('orgId', orgId);

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
      requireUuid('orgId', orgId);

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
