import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { resolveRestApiVersion, snykRestApi } from '../snyk/client.js';
import type { operations } from '../snyk/types/snyk-rest.d.ts';
import { requireUuid } from '../utils/helpers.js';
import {
  classifyProject,
  dedupeLedgerIssues,
  extractCodeDataFromIssue,
  extractPackageDataFromIssue,
  extractRiskScore,
  groupIssuesToAdvisories,
  type LedgerAdvisory,
  type LedgerIssue,
  type ProjectClassification,
  type ProjectKind,
  type RestIssue,
  type RestProject,
  toLedgerIssueType,
} from '../utils/ledger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ToolInput {
  orgId: string;
  targetId: string;
  status: 'open' | 'resolved' | 'ignored';
  issueTypes: Array<'package' | 'code'>;
  severities?: Array<'low' | 'medium' | 'high' | 'critical'>;
  includeAdvisoryGroups: boolean;
  includeIssueInstances: boolean;
  includeZeroIssueProjects: boolean;
  allowPartialResults: boolean;
  projectConcurrency: number;
}

interface LedgerSeedResult {
  query: {
    orgId: string;
    targetId: string;
    status: string;
    issueTypes: string[];
  };
  target: {
    id: string;
    displayName: string | null;
  };
  collection: {
    fetchedAt: string;
    projectCount: number;
    queriedProjectCount: number;
    skippedProjectCount: number;
    issueInstanceCount: number;
    advisoryCount: number;
    partial: boolean;
  };
  projects: {
    queried: Array<{
      projectId: string;
      projectName: string;
      kind: ProjectKind;
      workspacePackage: string | null;
    }>;
    skipped: Array<{
      projectId: string;
      projectName: string;
      reason: string;
    }>;
    failures: Array<{
      projectId: string;
      projectName: string;
      stage: string;
      message: string;
    }>;
  };
  issues: LedgerIssue[];
  advisories: LedgerAdvisory[];
}

type StatusFilter = 'open' | 'resolved' | 'ignored';

type RequestRateLimiter = {
  schedule<T>(operation: () => Promise<T>): Promise<T>;
  defer(waitMs: number): void;
};

const ISSUE_REQUEST_INTERVAL_MS = 500;
const DEFAULT_RETRY_AFTER_MS = 5_000;
const MAX_RATE_LIMIT_RETRIES = 4;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapIssueType(type: 'package' | 'code') {
  if (type === 'package') return 'package_vulnerability' as const;
  return 'code' as const;
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createRequestRateLimiter(minIntervalMs: number): RequestRateLimiter {
  let nextAvailableAt = 0;
  let gate = Promise.resolve();

  return {
    async schedule<T>(operation: () => Promise<T>) {
      const slot = gate.then(async () => {
        const waitMs = Math.max(0, nextAvailableAt - Date.now());
        if (waitMs > 0) {
          await delay(waitMs);
        }

        nextAvailableAt = Date.now() + minIntervalMs;
      });

      gate = slot.catch(() => undefined);
      await slot;

      return operation();
    },

    defer(waitMs: number) {
      nextAvailableAt = Math.max(nextAvailableAt, Date.now() + waitMs);
    },
  };
}

function parseRetryAfterMs(retryAfterHeader: string | null): number {
  if (!retryAfterHeader) return DEFAULT_RETRY_AFTER_MS;

  const trimmed = retryAfterHeader.trim();
  if (!trimmed) return DEFAULT_RETRY_AFTER_MS;

  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.max(0, Math.ceil(seconds * 1000));
  }

  const timestamp = Date.parse(trimmed);
  if (Number.isNaN(timestamp)) {
    return DEFAULT_RETRY_AFTER_MS;
  }

  return Math.max(0, timestamp - Date.now());
}

function parseNextQuery(url: string): Record<string, unknown> {
  const params = new URL(url).searchParams;
  const grouped = new Map<string, string[]>();

  for (const [key, value] of params.entries()) {
    const existing = grouped.get(key);
    if (existing) {
      existing.push(value);
    } else {
      grouped.set(key, [value]);
    }
  }

  const query: Record<string, unknown> = {};
  for (const [key, values] of grouped) {
    if (values.length === 1) {
      query[key] = coerceQueryValue(values[0] ?? '');
      continue;
    }

    query[key] = values.map((value) => coerceQueryValue(value));
  }

  return query;
}

function coerceQueryValue(value: string): boolean | number | string {
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

type ListIssuesQuery = operations['listOrgIssues']['parameters']['query'];

type ListProjectsQuery = operations['listOrgProjects']['parameters']['query'];

type ListIssuesPage =
  operations['listOrgIssues']['responses'][200]['content']['application/vnd.api+json'];

const restProjectSchema = z
  .object({
    id: z.string(),
    attributes: z.object({
      name: z.string(),
      type: z.string(),
      target_file: z.string().default(''),
    }),
  })
  .passthrough();

const restProjectPageSchema = z
  .object({
    data: z.array(restProjectSchema).default([]),
    links: z
      .object({
        next: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

type RestProjectPage = z.infer<typeof restProjectPageSchema>;

function getPageItems<T>(page: { data?: T[] } | null | undefined): T[] {
  return page?.data ?? [];
}

function getNextPageUrl(
  page:
    | {
        links?: {
          next?: string | { href: string };
        };
      }
    | null
    | undefined,
) {
  const next = page?.links?.next;
  return typeof next === 'string' ? next : next?.href;
}

function parseProjectPage(page: unknown): RestProjectPage {
  return restProjectPageSchema.parse(page);
}

function buildIssueQuery({
  apiVersion,
  issueType,
  severity,
  status,
  projectId,
}: {
  apiVersion: string;
  issueType: 'package' | 'code';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  status: StatusFilter;
  projectId: string;
}): ListIssuesQuery {
  const query: ListIssuesQuery = {
    version: apiVersion,
    limit: 100,
    type: mapIssueType(issueType),
    'scan_item.id': projectId,
    'scan_item.type': 'project',
  };

  if (severity) {
    query['effective_severity_level'] = [severity];
  }

  if (status === 'ignored') {
    query['ignored'] = true;
  } else if (status) {
    query['status'] = [status];
  }

  return query;
}

/**
 * Fetch ALL issues for a given project + type, handling pagination internally.
 */
async function fetchAllProjectIssues(
  orgId: string,
  projectId: string,
  issueType: 'package' | 'code',
  options: {
    apiVersion: string;
    rateLimiter: RequestRateLimiter;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    status: StatusFilter;
  },
): Promise<RestIssue[]> {
  const initialQuery = buildIssueQuery({
    apiVersion: options.apiVersion,
    issueType,
    severity: options.severity,
    status: options.status,
    projectId,
  });

  // First page
  const firstPage = await fetchIssuesPage(
    orgId,
    initialQuery,
    options.rateLimiter,
  );
  const items = getPageItems(firstPage);

  // Check for remaining pages by inspecting `meta`/`links`
  if (!firstPage) return items;

  let nextUrl = getNextPageUrl(firstPage);

  while (nextUrl) {
    const nextQuery = parseNextQuery(nextUrl);

    const nextPageData = await fetchIssuesPage(
      orgId,
      // Snyk's own `next` link encodes version/type/status correctly.
      // Cast through `unknown` because openapi-fetch requires typed query.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      nextQuery as unknown as any,
      options.rateLimiter,
    );

    const nextItems = getPageItems(nextPageData);
    items.push(...nextItems);

    if (!nextPageData) break;
    nextUrl = getNextPageUrl(nextPageData);
  }

  return items;
}

async function fetchIssuesPage(
  orgId: string,
  query: ListIssuesQuery,
  rateLimiter: RequestRateLimiter,
): Promise<ListIssuesPage> {
  for (let attempt = 0; attempt <= MAX_RATE_LIMIT_RETRIES; attempt += 1) {
    const result = await rateLimiter.schedule(() =>
      snykRestApi.client.GET('/orgs/{org_id}/issues', {
        params: {
          path: { org_id: orgId },
          query,
        },
      }),
    );

    if (result.response.status !== 429) {
      return snykRestApi.expectData(result);
    }

    const retryAfterMs = parseRetryAfterMs(
      result.response.headers.get('retry-after'),
    );

    rateLimiter.defer(retryAfterMs);

    if (attempt === MAX_RATE_LIMIT_RETRIES) {
      throw new Error(
        `Snyk REST API rate limit reached for org '${orgId}' after ${MAX_RATE_LIMIT_RETRIES + 1} attempts. ` +
          `Retry-After: ${retryAfterMs}ms.`,
      );
    }

    await delay(retryAfterMs);
  }

  throw new Error(
    `Snyk REST API rate limit retry loop ended unexpectedly for org '${orgId}'.`,
  );
}

async function fetchAllTargetProjects(
  orgId: string,
  targetId: string,
  apiVersion: string,
): Promise<RestProject[]> {
  const initialQuery: ListProjectsQuery = {
    version: apiVersion,
    limit: 100,
    target_id: [targetId],
  };

  const firstPage = parseProjectPage(
    snykRestApi.expectData<unknown>(
      await snykRestApi.client.GET('/orgs/{org_id}/projects', {
        params: {
          path: { org_id: orgId },
          query: initialQuery,
        },
      }),
    ),
  );

  const items = getPageItems(firstPage);

  if (!firstPage) return items;

  let nextUrl = getNextPageUrl(firstPage);

  while (nextUrl) {
    const nextPageData = parseProjectPage(
      snykRestApi.expectData<unknown>(
        await snykRestApi.client.GET('/orgs/{org_id}/projects', {
          params: {
            path: { org_id: orgId },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            query: parseNextQuery(nextUrl) as unknown as any,
          },
        }),
      ),
    );

    const nextItems = getPageItems(nextPageData);
    items.push(...nextItems);

    if (!nextPageData) break;
    nextUrl = getNextPageUrl(nextPageData);
  }

  return items;
}

async function fetchTargetDisplayName(
  orgId: string,
  targetId: string,
  apiVersion: string,
) {
  try {
    const targetResponse = snykRestApi.expectData(
      await snykRestApi.client.GET('/orgs/{org_id}/targets/{target_id}', {
        params: {
          path: { org_id: orgId, target_id: targetId },
          query: { version: apiVersion },
        },
      }),
    );
    const target = targetResponse?.data;
    return (target?.attributes?.display_name as string | undefined) ?? null;
  } catch {
    return null;
  }
}

function appendMappedIssues(
  targetIssues: LedgerIssue[],
  items: RestIssue[],
  project: ProjectClassification,
  targetId: string,
) {
  targetIssues.push(
    ...items.map((item) => mapItemToLedgerIssue(item, project, targetId)),
  );
}

// ---------------------------------------------------------------------------
// Main mapper: REST issue → LedgerIssue
// ---------------------------------------------------------------------------

function mapItemToLedgerIssue(
  item: RestIssue,
  project: ProjectClassification,
  targetId: string,
): LedgerIssue {
  const attrs = item.attributes;
  const riskScore = extractRiskScore(item);

  return {
    advisoryKey: attrs.key,
    restIssueId: item.id ?? '',
    issueKey: attrs.key,
    issueType: toLedgerIssueType(attrs.type),
    severity: attrs.effective_severity_level,
    riskScore,
    title: attrs.title,
    createdAt: attrs.created_at,
    status: attrs.status,
    projectId: project.projectId,
    projectName: project.projectName,
    workspacePackage: project.workspacePackage,
    targetId,
    package: extractPackageDataFromIssue(item),
    code: extractCodeDataFromIssue(item),
  };
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerLedgerSeedTool(server: McpServer) {
  server.registerTool(
    'snyk_get_target_ledger_seed',
    {
      description:
        'Ledger-seed endpoint: fetches ALL open package/code issues for all ' +
        'relevant projects of a Snyk target, then returns them normalised, ' +
        'project-annotated, and optionally pre-grouped into advisories. ' +
        'The output is ready to directly materialise an issues-ledger.json for ' +
        'remediation orchestration — no further detail calls needed. ' +
        'Use snyk_resolve_org_id and snyk_get_targets first to obtain orgId ' +
        'and targetId.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        targetId: z
          .string()
          .describe(
            'Snyk target ID (UUID). Use snyk_get_targets to discover targets for an org.',
          ),
        status: z
          .enum(['open', 'resolved', 'ignored'])
          .optional()
          .default('open')
          .describe('Filter by issue status. Default: open.'),
        issueTypes: z
          .array(z.enum(['package', 'code']))
          .optional()
          .default(['package', 'code'])
          .describe(
            'Which issue types to fetch. Default: both package and code.',
          ),
        severities: z
          .array(z.enum(['low', 'medium', 'high', 'critical']))
          .optional()
          .describe(
            'Filter by severity levels. Omit to include all severities.',
          ),
        includeAdvisoryGroups: z
          .boolean()
          .optional()
          .default(true)
          .describe(
            'Whether to return pre-grouped advisory summaries. Default: true.',
          ),
        includeIssueInstances: z
          .boolean()
          .optional()
          .default(true)
          .describe(
            'Whether to return the flat issue instances list. Default: true.',
          ),
        includeZeroIssueProjects: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            'Include projects with zero issues in the response. Default: false.',
          ),
        allowPartialResults: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            'If true, continue fetching even if some projects fail; failures ' +
              'are listed under projects.failures. Default: false.',
          ),
        projectConcurrency: z
          .number()
          .optional()
          .default(6)
          .describe(
            'Maximum concurrent project issue-fetch operations. Default: 6.',
          ),
      },
    },
    async ({
      orgId,
      targetId,
      status,
      issueTypes,
      severities,
      includeAdvisoryGroups,
      includeIssueInstances,
      includeZeroIssueProjects,
      allowPartialResults,
      projectConcurrency,
    }: ToolInput) => {
      requireUuid('orgId', orgId);
      requireUuid('targetId', targetId);

      const apiVersion = resolveRestApiVersion();
      const rateLimiter = createRequestRateLimiter(ISSUE_REQUEST_INTERVAL_MS);

      // -----------------------------------------------------------------
      // 1. Fetch projects for this target
      // -----------------------------------------------------------------
      const allProjects = (
        await fetchAllTargetProjects(orgId, targetId, apiVersion)
      ).map(classifyProject);

      // Fetch target display name
      const targetDisplayName = await fetchTargetDisplayName(
        orgId,
        targetId,
        apiVersion,
      );

      // -----------------------------------------------------------------
      // 2. Classify projects
      // -----------------------------------------------------------------
      const relevantProjects = allProjects.filter(
        (p) => p.kind === 'package' || p.kind === 'code',
      );
      let skippedProjects: LedgerSeedResult['projects']['skipped'] = allProjects
        .filter((p) => p.kind === 'container' || p.kind === 'unknown')
        .map((p) => ({
          projectId: p.projectId,
          projectName: p.projectName,
          reason:
            p.kind === 'container'
              ? 'container-project'
              : `unknown-project-type:${p.kind}`,
        }));

      // -----------------------------------------------------------------
      // 3. Fan out – fetch issues for each relevant project/type
      // -----------------------------------------------------------------
      const failures: LedgerSeedResult['projects']['failures'] = [];

      // Build tasks: for each project × each requested issue type
      const tasks: Array<{
        project: ProjectClassification;
        issueType: 'package' | 'code';
      }> = [];

      for (const project of relevantProjects) {
        for (const issueType of issueTypes) {
          // Skip code-type requests for projects classified as package-only
          if (issueType === 'code' && project.kind !== 'code') continue;
          // Skip package-type requests for projects classified as code-only
          if (issueType === 'package' && project.kind !== 'package') continue;
          tasks.push({ project, issueType });
        }
      }

      const allIssues: LedgerIssue[] = [];

      // Execute tasks with limited concurrency
      const concurrency = Math.max(1, projectConcurrency);
      for (let i = 0; i < tasks.length; i += concurrency) {
        const chunk = tasks.slice(i, i + concurrency);
        const chunkResults = await Promise.allSettled(
          chunk.map(async (task) => {
            const requestedSeverities =
              severities && severities.length > 0 ? severities : [undefined];

            for (const severity of requestedSeverities) {
              const items = await fetchAllProjectIssues(
                orgId,
                task.project.projectId,
                task.issueType,
                { apiVersion, rateLimiter, severity, status },
              );
              appendMappedIssues(allIssues, items, task.project, targetId);
            }
          }),
        );

        for (let j = 0; j < chunkResults.length; j++) {
          const result = chunkResults[j]!;
          const task = chunk[j]!;
          if (result.status === 'rejected') {
            failures.push({
              projectId: task.project.projectId,
              projectName: task.project.projectName,
              stage: 'list-project-issues',
              message:
                result.reason instanceof Error
                  ? result.reason.message
                  : String(result.reason),
            });
            if (!allowPartialResults) {
              throw new Error(
                `Failed to fetch issues for project ${task.project.projectName} (${task.project.projectId}). ` +
                  `Set allowPartialResults=true to continue. Error: ${String(result.reason)}`,
              );
            }
          }
        }
      }

      // -----------------------------------------------------------------
      // 4. Build result
      // -----------------------------------------------------------------
      const uniqueIssues = dedupeLedgerIssues(allIssues);

      const advisories = includeAdvisoryGroups
        ? groupIssuesToAdvisories(uniqueIssues)
        : [];

      const failedProjectIds = new Set(
        failures.map((failure) => failure.projectId),
      );
      const issueProjectIds = new Set(
        uniqueIssues.map((issue) => issue.projectId),
      );
      const emptyRelevantProjects = relevantProjects.filter(
        (project) =>
          !issueProjectIds.has(project.projectId) &&
          !failedProjectIds.has(project.projectId),
      );

      const queriedProjects = includeZeroIssueProjects
        ? relevantProjects
        : relevantProjects.filter(
            (project) =>
              issueProjectIds.has(project.projectId) ||
              failedProjectIds.has(project.projectId),
          );

      // Filter out zero-issue projects unless client asks to keep them
      if (!includeZeroIssueProjects) {
        if (emptyRelevantProjects.length > 0) {
          skippedProjects = [
            ...skippedProjects,
            ...emptyRelevantProjects.map((p) => ({
              projectId: p.projectId,
              projectName: p.projectName,
              reason: 'zero-issue-project' as const,
            })),
          ];
        }
      }

      const result: LedgerSeedResult = {
        query: {
          orgId,
          targetId,
          status,
          issueTypes,
        },
        target: {
          id: targetId,
          displayName: targetDisplayName,
        },
        collection: {
          fetchedAt: new Date().toISOString(),
          projectCount: allProjects.length,
          queriedProjectCount: queriedProjects.length,
          skippedProjectCount: skippedProjects.length,
          issueInstanceCount: uniqueIssues.length,
          advisoryCount: advisories.length,
          partial: failures.length > 0,
        },
        projects: {
          queried: queriedProjects.map((p) => ({
            projectId: p.projectId,
            projectName: p.projectName,
            kind: p.kind,
            workspacePackage: p.workspacePackage,
          })),
          skipped: skippedProjects,
          failures,
        },
        issues: includeIssueInstances ? uniqueIssues : [],
        advisories,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
