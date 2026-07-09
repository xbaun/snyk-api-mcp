import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { resolveRestApiVersion, snykRestApi } from '../snyk/client.js';
import type { operations } from '../snyk/types/snyk-rest.d.ts';
import { requireUuid } from '../utils/helpers.js';
import type {
  LedgerAdvisory,
  LedgerIssue,
  ProjectClassification,
  RestIssue,
  RestProject,
} from '../utils/ledger.js';
import {
  classifyProject,
  dedupeLedgerIssues,
  extractCodeLocationFromIssue,
  extractPackageIdentityFromIssue,
  extractRiskScore,
  groupIssuesToAdvisories,
  sortLedgerIssues,
  toLedgerIssueType,
} from '../utils/ledger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TargetToolInput {
  orgId: string;
  targetId: string;
}

interface ProjectToolInput {
  orgId: string;
  projectId: string;
}

interface TargetLedgerSeedResult {
  $schema: string;
  query: {
    orgId: string;
    targetId: string;
    status: 'open';
    issueTypes: Array<'package_vulnerability' | 'code'>;
  };
  target: {
    id: string;
    displayName: string | null;
  };
  collection: {
    fetchedAt: string;
    projectCount: number;
    issueCount: number;
    advisoryCount: number;
  };
  issues: LedgerIssue[];
  advisories: LedgerAdvisory[];
}

interface ProjectLedgerSeedResult {
  $schema: string;
  query: {
    orgId: string;
    projectId: string;
    status: 'open';
    issueTypes: Array<'package_vulnerability' | 'code'>;
  };
  project: {
    id: string;
    name: string;
    type: string;
    kind: ProjectClassification['kind'];
    targetId: string | null;
    workspacePackage: string | null;
  };
  collection: {
    fetchedAt: string;
    projectCount: number;
    issueCount: number;
    advisoryCount: number;
  };
  issues: LedgerIssue[];
  advisories: LedgerAdvisory[];
}

type StatusFilter = 'open' | 'resolved' | 'ignored';
type SeedIssueType = 'package_vulnerability' | 'code';

type RequestRateLimiter = {
  schedule<T>(operation: () => Promise<T>): Promise<T>;
  defer(waitMs: number): void;
};

const ISSUE_REQUEST_INTERVAL_MS = 500;
const DEFAULT_RETRY_AFTER_MS = 5_000;
const MAX_RATE_LIMIT_RETRIES = 4;
const PROJECT_CONCURRENCY = 6;
const LEDGER_SEED_STATUS = 'open' as const;
const LEDGER_SEED_ISSUE_TYPES = ['package_vulnerability', 'code'] as const;
const TARGET_LEDGER_SEED_SCHEMA_PATH =
  '../../.github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json';
const PROJECT_LEDGER_SEED_SCHEMA_PATH =
  '../../.github/skills/snyk-session-init/schemas/project-issues-ledger-seed.schema.json';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    relationships: z
      .object({
        target: z
          .object({
            data: z.union([
              z.object({ id: z.string() }).passthrough(),
              z.array(z.object({ id: z.string() }).passthrough()),
            ]),
          })
          .optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

const restProjectDetailSchema = z
  .object({
    data: restProjectSchema.optional(),
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
type RestProjectResource = z.infer<typeof restProjectSchema>;

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

function parseProjectDetail(page: unknown) {
  return restProjectDetailSchema.parse(page);
}

function extractTargetId(project: RestProjectResource): string | null {
  const targetData = project.relationships?.target?.data;

  if (Array.isArray(targetData)) {
    return targetData[0]?.id ?? null;
  }

  return targetData?.id ?? null;
}

function isLedgerRelevantProject(project: ProjectClassification) {
  return project.kind === 'package' || project.kind === 'code';
}

function buildIssueQuery({
  apiVersion,
  issueType,
  status,
  projectId,
}: {
  apiVersion: string;
  issueType: SeedIssueType;
  status: StatusFilter;
  projectId: string;
}): ListIssuesQuery {
  const query: ListIssuesQuery = {
    version: apiVersion,
    limit: 100,
    type: issueType,
    'scan_item.id': projectId,
    'scan_item.type': 'project',
  };

  if (status === 'ignored') {
    query['ignored'] = true;
  } else {
    query['status'] = [status];
  }

  return query;
}

async function fetchAllProjectIssues(
  orgId: string,
  projectId: string,
  issueType: SeedIssueType,
  options: {
    apiVersion: string;
    rateLimiter: RequestRateLimiter;
    status: StatusFilter;
  },
): Promise<RestIssue[]> {
  const initialQuery = buildIssueQuery({
    apiVersion: options.apiVersion,
    issueType,
    status: options.status,
    projectId,
  });

  const firstPage = await fetchIssuesPage(
    orgId,
    initialQuery,
    options.rateLimiter,
  );
  const items = getPageItems(firstPage);

  if (!firstPage) return items;

  let nextUrl = getNextPageUrl(firstPage);

  while (nextUrl) {
    const nextQuery = parseNextQuery(nextUrl);
    const nextPageData = await fetchIssuesPage(
      orgId,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      nextQuery as unknown as any,
      options.rateLimiter,
    );

    items.push(...getPageItems(nextPageData));
    nextUrl = nextPageData ? getNextPageUrl(nextPageData) : undefined;
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

    items.push(...getPageItems(nextPageData));
    nextUrl = getNextPageUrl(nextPageData);
  }

  return items;
}

async function fetchProjectById(
  orgId: string,
  projectId: string,
  apiVersion: string,
): Promise<RestProjectResource> {
  const detail = parseProjectDetail(
    snykRestApi.expectData<unknown>(
      await snykRestApi.client.GET('/orgs/{org_id}/projects/{project_id}', {
        params: {
          path: { org_id: orgId, project_id: projectId },
          query: { version: apiVersion },
        },
      }),
    ),
  );

  if (!detail.data) {
    throw new Error(
      `Snyk project '${projectId}' returned no project resource.`,
    );
  }

  return detail.data;
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

function mapItemsToLedgerIssues(
  items: RestIssue[],
  project: ProjectClassification,
) {
  return items.map((item) => mapItemToLedgerIssue(item, project));
}

function mapItemToLedgerIssue(
  item: RestIssue,
  project: ProjectClassification,
): LedgerIssue {
  const attrs = item.attributes;
  const riskScore = extractRiskScore(item);
  const packageIdentity =
    attrs.type === 'package_vulnerability'
      ? extractPackageIdentityFromIssue(item, project.projectType)
      : {};
  const codeLocation =
    attrs.type === 'code' ? extractCodeLocationFromIssue(item) : {};

  return {
    advisoryKey: attrs.key,
    restIssueId: item.id ?? '',
    issueKey: attrs.key,
    issueType: toLedgerIssueType(attrs.type),
    severity: attrs.effective_severity_level,
    riskScore,
    title: attrs.title,
    createdAt: attrs.created_at,
    projectId: project.projectId,
    projectName: project.projectName,
    ...(project.workspacePackage
      ? { workspacePackage: project.workspacePackage }
      : {}),
    ...packageIdentity,
    ...codeLocation,
  };
}

function buildLedgerSeedTasks(projects: ProjectClassification[]) {
  const tasks: Array<{
    project: ProjectClassification;
    issueType: SeedIssueType;
  }> = [];

  for (const project of projects) {
    for (const issueType of LEDGER_SEED_ISSUE_TYPES) {
      if (issueType === 'code' && project.kind !== 'code') continue;
      if (issueType === 'package_vulnerability' && project.kind !== 'package') {
        continue;
      }

      tasks.push({ project, issueType });
    }
  }

  return tasks;
}

async function collectLedgerIssuesForProjects(
  orgId: string,
  projects: ProjectClassification[],
  options: {
    apiVersion: string;
    rateLimiter: RequestRateLimiter;
    status: StatusFilter;
  },
) {
  const tasks = buildLedgerSeedTasks(projects);
  const allIssues: LedgerIssue[] = [];

  for (let i = 0; i < tasks.length; i += PROJECT_CONCURRENCY) {
    const chunk = tasks.slice(i, i + PROJECT_CONCURRENCY);
    const chunkResults = await Promise.allSettled(
      chunk.map(async (task) => {
        const items = await fetchAllProjectIssues(
          orgId,
          task.project.projectId,
          task.issueType,
          options,
        );

        return {
          task,
          issues: mapItemsToLedgerIssues(items, task.project),
        };
      }),
    );

    for (let j = 0; j < chunkResults.length; j += 1) {
      const result = chunkResults[j]!;
      const task = chunk[j]!;

      if (result.status === 'rejected') {
        throw new Error(
          `Failed to fetch issues for project ${task.project.projectName} (${task.project.projectId}). ` +
            `${result.reason instanceof Error ? result.reason.message : String(result.reason)}`,
        );
      }

      allIssues.push(...result.value.issues);
    }
  }

  return sortLedgerIssues(dedupeLedgerIssues(allIssues));
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerLedgerSeedTool(server: McpServer) {
  server.registerTool(
    'snyk_get_target_ledger_seed',
    {
      description:
        'Fetch the canonical issues-ledger seed for one Snyk target. ' +
        'This enumerates all relevant projects, paginates all open package_vulnerability and code issues, ' +
        'and returns a minimal seed document with flat canonical issues[] plus grouped advisories[]. ' +
        'Persist the response unchanged as issues-ledger-seed.json. ledger.py init materializes from advisories[] and only validates issues[]; ' +
        'do not rename issueKey/projectId/issueType to legacy aliases like key/scanItemId/type. ' +
        'Use snyk_resolve_org_id and snyk_get_targets first to obtain orgId and targetId.',
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
      },
    },
    async ({ orgId, targetId }: TargetToolInput) => {
      requireUuid('orgId', orgId);
      requireUuid('targetId', targetId);

      const apiVersion = resolveRestApiVersion();
      const rateLimiter = createRequestRateLimiter(ISSUE_REQUEST_INTERVAL_MS);
      const allProjects = (
        await fetchAllTargetProjects(orgId, targetId, apiVersion)
      ).map(classifyProject);
      const targetDisplayName = await fetchTargetDisplayName(
        orgId,
        targetId,
        apiVersion,
      );
      const relevantProjects = allProjects.filter(isLedgerRelevantProject);
      const issues = await collectLedgerIssuesForProjects(
        orgId,
        relevantProjects,
        {
          apiVersion,
          rateLimiter,
          status: LEDGER_SEED_STATUS,
        },
      );
      const advisories = groupIssuesToAdvisories(issues);

      const result: TargetLedgerSeedResult = {
        $schema: TARGET_LEDGER_SEED_SCHEMA_PATH,
        query: {
          orgId,
          targetId,
          status: LEDGER_SEED_STATUS,
          issueTypes: [...LEDGER_SEED_ISSUE_TYPES],
        },
        target: {
          id: targetId,
          displayName: targetDisplayName,
        },
        collection: {
          fetchedAt: new Date().toISOString(),
          projectCount: allProjects.length,
          issueCount: issues.length,
          advisoryCount: advisories.length,
        },
        issues,
        advisories,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.registerTool(
    'snyk_get_project_ledger_seed',
    {
      description:
        'Fetch the canonical issues-ledger seed for one Snyk project. ' +
        'This paginates all open package_vulnerability and code issues for exactly one project ' +
        'and returns a minimal seed document with flat canonical issues[] plus grouped advisories[]. ' +
        'Persist the response unchanged as issues-ledger-seed.json. ledger.py init materializes from advisories[] and only validates issues[]; ' +
        'do not rename issueKey/projectId/issueType to legacy aliases like key/scanItemId/type. ' +
        'Use snyk_get_projects first to obtain orgId and projectId.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        projectId: z
          .string()
          .describe(
            'Snyk project ID (UUID). Use snyk_get_projects to discover projects for an org or target.',
          ),
      },
    },
    async ({ orgId, projectId }: ProjectToolInput) => {
      requireUuid('orgId', orgId);
      requireUuid('projectId', projectId);

      const apiVersion = resolveRestApiVersion();
      const rateLimiter = createRequestRateLimiter(ISSUE_REQUEST_INTERVAL_MS);
      const rawProject = await fetchProjectById(orgId, projectId, apiVersion);
      const project = classifyProject(rawProject);

      if (!isLedgerRelevantProject(project)) {
        throw new Error(
          `Project '${project.projectName}' (${project.projectId}) has type '${project.projectType}' classified as '${project.kind}'. ` +
            "Only 'package' and 'code' projects are supported by snyk_get_project_ledger_seed.",
        );
      }

      const issues = await collectLedgerIssuesForProjects(orgId, [project], {
        apiVersion,
        rateLimiter,
        status: LEDGER_SEED_STATUS,
      });
      const advisories = groupIssuesToAdvisories(issues);

      const result: ProjectLedgerSeedResult = {
        $schema: PROJECT_LEDGER_SEED_SCHEMA_PATH,
        query: {
          orgId,
          projectId,
          status: LEDGER_SEED_STATUS,
          issueTypes: [...LEDGER_SEED_ISSUE_TYPES],
        },
        project: {
          id: project.projectId,
          name: project.projectName,
          type: project.projectType,
          kind: project.kind,
          targetId: extractTargetId(rawProject),
          workspacePackage: project.workspacePackage,
        },
        collection: {
          fetchedAt: new Date().toISOString(),
          projectCount: 1,
          issueCount: issues.length,
          advisoryCount: advisories.length,
        },
        issues,
        advisories,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
