import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { env } from '../config.js';
import { snykGet } from '../snyk/client.js';
import type {
  IssueSummary,
  NormalizedPathNode,
  PathSummary,
  SnykItem,
  SnykPathNode,
} from '../utils/helpers.js';
import {
  formatPackageLabel,
  normalizePathNode,
  parsePackageFixVersions,
  parseUpgradePackageValue,
  selectRelevantFixVersion,
  uniqueStrings,
} from '../utils/helpers.js';
import { derivePurl, encodePurl, requirePurlInput } from '../utils/purl.js';
import { resolveProjectIssueIds, summarizeIssueV3 } from './issues.js';

// ---------------------------------------------------------------------------
// Extract fix versions from an issue (domain-specific, stays here)
// ---------------------------------------------------------------------------

function extractIssueFixVersions(issue: IssueSummary | null): string[] {
  if (!issue) return [];

  const coordinates = Array.isArray(issue.coordinates) ? issue.coordinates : [];
  const versions = coordinates.flatMap((coordinate) => {
    const remedies = Array.isArray(coordinate.remedies)
      ? coordinate.remedies
      : [];
    return remedies.flatMap((remedy: Record<string, unknown>) => {
      const details: Record<string, unknown> =
        typeof remedy?.details === 'object' && remedy?.details !== null
          ? (remedy.details as Record<string, unknown>)
          : {};
      return [
        ...parseUpgradePackageValue(details['upgradePackage']),
        ...parseUpgradePackageValue(details['upgrade_package']),
        ...parsePackageFixVersions(
          typeof remedy?.description === 'string' ? remedy.description : null,
        ),
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
        'Compose a UI-like analysis for a single open source issue in a specific project. ' +
        'Combines REST issue-instance metadata, v1 dependency paths, and package vulnerability metadata ' +
        'so agents can access introduced-through parents, the relevant vulnerable-package fix version, ' +
        'a project remediation hint, and detailed dependency paths in one response.',
      inputSchema: {
        orgId: z.string().describe('Snyk Organization ID.'),
        projectId: z
          .string()
          .describe('Snyk Project ID in which the issue appears.'),
        issueId: z
          .string()
          .describe(
            'Issue identifier. Prefer the v1 vulnerability ID (for example SNYK-JS-ESBUILD-17750822). REST UUID issue IDs are also accepted.',
          ),
        packageType: z
          .string()
          .optional()
          .default('npm')
          .describe(
            'Package ecosystem for constructing a PURL when package metadata is derived from paths. Example: npm.',
          ),
        packageName: z
          .string()
          .optional()
          .describe(
            'Optional package name override if it cannot be derived from the dependency path.',
          ),
        packageVersion: z
          .string()
          .optional()
          .describe(
            'Optional package version override if it cannot be derived from the dependency path.',
          ),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
        perPage: z
          .number()
          .optional()
          .default(1000)
          .describe(
            'How many project issue paths to request from v1 (max 1000).',
          ),
      },
    },
    async ({
      orgId,
      projectId,
      issueId,
      packageType,
      packageName,
      packageVersion,
      version,
      perPage,
    }) => {
      const apiVersion = version || env.SNYK_API_VERSION;
      const { restIssue, restIssueId, v1IssueId } =
        await resolveProjectIssueIds(orgId, projectId, issueId, apiVersion);

      const pathData = await snykGet(
        `/v1/org/${encodeURIComponent(orgId)}` +
          `/project/${encodeURIComponent(projectId)}` +
          `/issue/${encodeURIComponent(v1IssueId)}` +
          `/paths?perPage=${encodeURIComponent(String(perPage))}&page=1`,
        'application/json',
      );

      const rawPaths = Array.isArray(pathData?.paths) ? pathData.paths : [];
      const pathSummaries = rawPaths.map(summarizeIssuePath);
      const shortestPath = pathSummaries[0] ?? null;

      const derivedPackageName =
        packageName ?? shortestPath?.vulnerablePackage?.name ?? null;
      const derivedPackageVersion =
        packageVersion ?? shortestPath?.vulnerablePackage?.version ?? null;
      const purl = derivePurl(
        packageType,
        undefined,
        derivedPackageName ?? undefined,
        derivedPackageVersion ?? undefined,
      );

      let packageIssue: IssueSummary | null = null;
      if (purl) {
        const pkgData = await snykGet(
          `/rest/orgs/${encodeURIComponent(orgId)}/packages/${encodePurl(purl)}/issues?version=${encodeURIComponent(apiVersion)}&limit=1000`,
        );
        const pkgItems = Array.isArray(pkgData?.data) ? pkgData.data : [];
        const match = pkgItems.find((item: SnykItem) => {
          const attrs = item?.attributes ?? {};
          return item?.id === v1IssueId || attrs?.key === v1IssueId;
        });
        packageIssue = match ? summarizeIssueV3(match) : null;
      }

      const remediationFixVersions = uniqueStrings([
        ...extractIssueFixVersions(packageIssue),
        ...extractIssueFixVersions(restIssue),
      ]);
      const selectedPackageFixVersion = selectRelevantFixVersion(
        derivedPackageVersion,
        remediationFixVersions,
      );

      const directDependencies = Array.from(
        new Set(
          pathSummaries
            .map((path: PathSummary) => path.directDependency)
            .filter(Boolean)
            .map((dep: NormalizedPathNode) =>
              formatPackageLabel(dep.name, dep.version),
            ),
        ),
      );

      const result = {
        query: {
          orgId,
          projectId,
          issueId,
          resolvedRestIssueId: restIssueId,
          resolvedV1IssueId: v1IssueId,
          apiVersion,
        },
        issue: {
          restIssueId,
          v1IssueId,
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
          name: derivedPackageName,
          version: derivedPackageVersion,
          purl,
          fixedIn: selectedPackageFixVersion,
          vulnerableRangeFromDb:
            packageIssue?.description?.match(/versions\s+(.+?)\n/i)?.[1] ??
            null,
        },
        issueContext: {
          introducedThrough: directDependencies,
          remediation: shortestPath?.remediation ?? null,
          exploitMaturity:
            (restIssue?.risk?.factors as Record<string, unknown> | undefined)
              ?.exploitMaturity ?? null,
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
        'Get all Snyk security issues for a package (PURL). ' +
        'Returns up to 1000 issues — the allIssues payload can be large. ' +
        'Use issueRef to filter to a single issue when possible.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug.',
          ),
        purl: z
          .string()
          .optional()
          .describe('Package URL, e.g. pkg:npm/lodash@4.17.15'),
        packageType: z
          .string()
          .optional()
          .default('npm')
          .describe(
            'Optional package ecosystem when constructing a PURL from name+version. Example: npm.',
          ),
        packageName: z
          .string()
          .optional()
          .describe(
            'Optional package name when you prefer structured package inputs over a raw PURL.',
          ),
        packageVersion: z
          .string()
          .optional()
          .describe(
            'Optional package version when you prefer structured package inputs over a raw PURL.',
          ),
        issueRef: z
          .string()
          .optional()
          .describe(
            'Optional Snyk issue ID or CVE, e.g. SNYK-JS-LODASH-590103 or CVE-2020-8203',
          ),
        version: z
          .string()
          .optional()
          .describe('Optional Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({
      orgId,
      purl,
      packageType,
      packageName,
      packageVersion,
      issueRef,
      version,
    }) => {
      const apiVersion = version || env.SNYK_API_VERSION;
      const resolvedPurl = requirePurlInput(
        packageType,
        purl,
        packageName,
        packageVersion,
      );

      const encodedPurl = encodePurl(resolvedPurl);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/packages/${encodedPurl}/issues?version=${encodeURIComponent(apiVersion)}&limit=1000`,
      );

      const items = Array.isArray(data?.data) ? data.data : [];
      const issue = issueRef
        ? items.find((item: SnykItem) => {
            const id = item?.id ?? '';
            const attrs = item?.attributes ?? {};
            const rawIdentifiers = attrs['identifiers'] as
              Record<string, string[]> | undefined;
            const identifiers = [
              id,
              attrs['key'] as string | undefined,
              ...(rawIdentifiers?.CVE ?? []),
              ...(rawIdentifiers?.CWE ?? []),
              ...(Array.isArray(attrs.problems)
                ? (attrs.problems as Record<string, unknown>[]).map(
                    (p: Record<string, unknown>) => p.id as string,
                  )
                : []),
            ].filter(Boolean) as string[];
            return identifiers.some(
              (v) => v.toLowerCase() === issueRef.toLowerCase(),
            );
          })
        : undefined;

      const result = {
        query: {
          orgId,
          purl: resolvedPurl,
          packageType,
          packageName,
          packageVersion,
          issueRef,
          apiVersion,
        },
        matchedIssue: issue ? summarizeIssueV3(issue) : null,
        allIssuesCount: items.length,
        allIssues: items.length <= 50 ? items.map(summarizeIssueV3) : undefined,
        allIssuesTruncated: items.length > 50,
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
        'Get the project issue paths for the last Snyk analysis. ' +
        'Accepts either a V1 Snyk issue ID (e.g. SNYK-JS-LODASH-590103) or a REST issue UUID and resolves it to the V1 issue ID automatically.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug.',
          ),
        projectId: z.string().describe('Snyk Project ID'),
        issueId: z
          .string()
          .describe(
            'Snyk vulnerability issue ID (SNYK-...) or REST issue UUID.',
          ),
        page: z.number().optional().default(1),
        perPage: z.number().optional().default(1000),
        version: z
          .string()
          .optional()
          .describe(
            'Snyk REST API version used when a REST issue UUID must be resolved to a V1 issue ID.',
          ),
      },
    },
    async ({ orgId, projectId, issueId, page, perPage, version }) => {
      const apiVersion = version || env.SNYK_API_VERSION;
      const { restIssueId, v1IssueId } = await resolveProjectIssueIds(
        orgId,
        projectId,
        issueId,
        apiVersion,
      );

      const data = await snykGet(
        `/v1/org/${encodeURIComponent(orgId)}` +
          `/project/${encodeURIComponent(projectId)}` +
          `/issue/${encodeURIComponent(v1IssueId)}` +
          `/paths?perPage=${encodeURIComponent(String(perPage))}&page=${encodeURIComponent(String(page))}`,
        'application/json',
      );

      const result = {
        query: {
          orgId,
          projectId,
          issueId,
          resolvedRestIssueId: restIssueId,
          resolvedV1IssueId: v1IssueId,
          page,
          perPage,
          apiVersion,
        },
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
