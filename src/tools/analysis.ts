import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import {
  resolveRestApiVersion,
  snykRestApi,
  snykV1Api,
} from '../snyk/client.js';
import type {
  NormalizedIssueSummary,
  NormalizedPathNode,
  PathSummary,
  SnykPathNode,
} from '../utils/helpers.js';
import {
  formatPackageLabel,
  normalizePathNode,
  parsePackageFixVersions,
  requireRestIssueUuid,
  requireUuid,
  selectRelevantFixVersion,
  uniqueStrings,
} from '../utils/helpers.js';
import { encodePurl } from '../utils/purl.js';
import {
  resolveIssueKeyFromRestId,
  summarizePackageVulnerability,
} from './issues.js';

// ---------------------------------------------------------------------------
// Extract fix versions from an issue (domain-specific, stays here)
// ---------------------------------------------------------------------------

function extractIssueFixVersions(
  issue: NormalizedIssueSummary | null,
): string[] {
  if (!issue) return [];

  const coordinates = issue.coordinates;
  const versions = coordinates.flatMap((coordinate) => {
    return coordinate.remedies.flatMap((remedy) => {
      return [
        ...remedy.details.upgradePackage,
        ...(remedy.details.fixedIn ?? []),
        ...parsePackageFixVersions(remedy.description ?? null),
      ];
    });
  });

  return uniqueStrings([
    ...versions,
    ...parsePackageFixVersions(issue?.description ?? null),
  ]);
}

function summarizeIssuePath(path: SnykPathNode[]): PathSummary {
  const nodes = (Array.isArray(path) ? path : []).map(normalizePathNode);
  const first = nodes[0] ?? null;
  const last = nodes[nodes.length - 1] ?? null;
  const pathString = nodes
    .map((node: NormalizedPathNode) =>
      formatPackageLabel(node.name, node.version),
    )
    .join(' › ');

  let remediation: string | null = null;
  if (first?.fixVersion) {
    remediation =
      first.fixVersion === first.version
        ? `Re-lock transitive dependencies; direct dependency ${first.name}@${first.version} is already at the fixable parent version ${first.fixVersion}.`
        : `Upgrade direct dependency ${first.name} from ${first.version ?? 'unknown'} to ${first.fixVersion}.`;
  }

  return {
    directDependency: first
      ? {
          name: first.name,
          version: first.version,
          fixVersion: first.fixVersion,
        }
      : null,
    vulnerablePackage: last
      ? {
          name: last.name,
          version: last.version,
        }
      : null,
    pathLength: nodes.length,
    path: nodes,
    pathString,
    remediation: remediation ?? 'No remediation path available.',
  };
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerAnalysisTools(server: McpServer) {
  // -----------------------------------------------------------------------
  // snyk_get_project_issue_analysis
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_project_issue_analysis',
    {
      description:
        'Get combined analysis for a specific project issue and package PURL. ' +
        'Requires an exact REST issue UUID and an exact package PURL.',
      inputSchema: {
        orgId: z.string().describe('Snyk Organization ID.'),
        projectId: z
          .string()
          .describe('Snyk Project ID in which the issue appears.'),
        restIssueId: z
          .string()
          .describe(
            "Snyk REST issue UUID, e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'.",
          ),
        purl: z
          .string()
          .describe('Exact package URL, e.g. pkg:npm/lodash@4.17.15'),
        perPage: z
          .number()
          .optional()
          .default(1000)
          .describe('How many project issue paths to request (max 1000).'),
      },
    },
    async ({ orgId, projectId, restIssueId, purl, perPage }) => {
      requireUuid('orgId', orgId);
      requireUuid('projectId', projectId);

      const apiVersion = resolveRestApiVersion();
      requireRestIssueUuid('snyk_get_project_issue_analysis', restIssueId);

      const { restIssue, issueKey } = await resolveIssueKeyFromRestId(
        orgId,
        restIssueId,
        apiVersion,
      );

      const pathData = snykV1Api.expectData(
        await snykV1Api.client.GET(
          '/org/{orgId}/project/{projectId}/issue/{issueId}/paths',
          {
            params: {
              path: { orgId, projectId, issueId: issueKey },
              query: { perPage, page: 1 },
            },
          },
        ),
      );

      const rawPaths = (
        Array.isArray(pathData?.paths) ? pathData.paths : []
      ) as SnykPathNode[][];
      const pathSummaries = rawPaths.map(summarizeIssuePath);
      const shortestPath = pathSummaries[0] ?? null;

      const pkgData = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/packages/{purl}/issues', {
          params: {
            path: { org_id: orgId, purl: encodePurl(purl) },
            query: { version: apiVersion, limit: 1000 },
          },
        }),
      );
      const pkgItems = Array.isArray(pkgData?.data) ? pkgData.data : [];
      const vulnerabilityIds = new Set(
        restIssue.problems
          .filter((problem) => problem.type === 'vulnerability')
          .map((problem) => problem.id)
          .filter((id): id is string => Boolean(id)),
      );
      const match = pkgItems.find(
        (item) => typeof item.id === 'string' && vulnerabilityIds.has(item.id),
      );
      const packageIssue = match ? summarizePackageVulnerability(match) : null;

      const remediationFixVersions = uniqueStrings([
        ...extractIssueFixVersions(packageIssue),
        ...extractIssueFixVersions(restIssue),
      ]);
      const selectedPackageFixVersion = selectRelevantFixVersion(
        shortestPath?.vulnerablePackage?.version ?? null,
        remediationFixVersions,
      );

      const directDependencies = Array.from(
        new Set(
          pathSummaries
            .map((path: PathSummary) => path.directDependency)
            .filter(Boolean)
            .map((dep: PathSummary['directDependency']) =>
              dep ? formatPackageLabel(dep.name, dep.version) : '',
            ),
        ),
      );

      const result = {
        query: { orgId, projectId, restIssueId, purl },
        issue: {
          restIssueId,
          issueKey,
          vulnerabilityId: packageIssue?.vulnerabilityId ?? null,
          title: restIssue?.title ?? packageIssue?.title ?? null,
          severity:
            restIssue?.effectiveSeverityLevel ??
            packageIssue?.effectiveSeverityLevel ??
            null,
          status: restIssue?.status ?? null,
          risk: restIssue?.risk ?? null,
          problems: restIssue?.problems ?? packageIssue?.problems ?? [],
          classes: restIssue?.classes ?? packageIssue?.classes ?? [],
        },
        package: {
          purl,
          vulnerabilityId: packageIssue?.vulnerabilityId ?? null,
          issueKey: packageIssue?.issueKey ?? issueKey,
          fixedIn: selectedPackageFixVersion,
          vulnerableRangeFromDb:
            packageIssue?.description?.match(/versions\s+(.+?)\n/i)?.[1] ??
            null,
        },
        issueContext: {
          introducedThrough: directDependencies,
          remediation: shortestPath?.remediation ?? null,
          exploitMaturity:
            restIssue.risk.exploitMaturityLevels?.map((level) => level.level) ??
            null,
          detailedPathsCount: pathSummaries.length,
          shortestPath: shortestPath?.pathString ?? null,
        },
        overview: packageIssue?.description ?? restIssue?.description ?? null,
        projectIssuePaths: {
          snapshotId: pathData?.snapshotId ?? null,
          total: pathData?.total ?? pathSummaries.length,
          paths: pathSummaries,
        },
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // -----------------------------------------------------------------------
  // snyk_get_package_issue_description
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_package_issue_description',
    {
      description:
        'Get Snyk direct package vulnerabilities for a package PURL. ' +
        'Returns up to 1000 issues — the payload can be large.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug.',
          ),
        purl: z.string().describe('Package URL, e.g. pkg:npm/lodash@4.17.15'),
      },
    },
    async ({ orgId, purl }) => {
      requireUuid('orgId', orgId);

      const apiVersion = resolveRestApiVersion();
      const encodedPurl = encodePurl(purl);

      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/packages/{purl}/issues', {
          params: {
            path: { org_id: orgId, purl: encodedPurl },
            query: { version: apiVersion, limit: 1000 },
          },
        }),
      );

      const items = Array.isArray(data?.data) ? data.data : [];

      const result = {
        query: { orgId, purl },
        vulnerabilityCount: items.length,
        packageVulnerabilities:
          items.length <= 50
            ? items.map(summarizePackageVulnerability)
            : undefined,
        vulnerabilitiesTruncated: items.length > 50,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // -----------------------------------------------------------------------
  // snyk_get_project_issue_paths
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_project_issue_paths',
    {
      description:
        'Get the dependency paths for a project issue from the latest Snyk analysis. ' +
        'Expects a Snyk REST issue UUID and resolves the underlying issue key internally.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug.',
          ),
        projectId: z.string().describe('Snyk Project ID'),
        restIssueId: z
          .string()
          .describe(
            "Snyk REST issue UUID, e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'.",
          ),
        page: z.number().optional().default(1),
        perPage: z.number().optional().default(1000),
      },
    },
    async ({ orgId, projectId, restIssueId, page, perPage }) => {
      requireUuid('orgId', orgId);
      requireUuid('projectId', projectId);

      const apiVersion = resolveRestApiVersion();
      requireRestIssueUuid('snyk_get_project_issue_paths', restIssueId);

      const { issueKey } = await resolveIssueKeyFromRestId(
        orgId,
        restIssueId,
        apiVersion,
      );

      const data = snykV1Api.expectData(
        await snykV1Api.client.GET(
          '/org/{orgId}/project/{projectId}/issue/{issueId}/paths',
          {
            params: {
              path: { orgId, projectId, issueId: issueKey },
              query: { perPage, page },
            },
          },
        ),
      );

      const result = {
        query: { orgId, projectId, restIssueId, page, perPage },
        issueKey,
        snapshotId: data?.snapshotId,
        total: data?.total,
        shortestPath: Array.isArray(data?.paths) ? data.paths[0] : undefined,
        paths: data?.paths,
        links: data?.links,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
