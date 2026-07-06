import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SNYK_TOKEN = process.env.SNYK_TOKEN;
const SNYK_API_BASE = process.env.SNYK_API_BASE ?? "https://api.eu.snyk.io";
const SNYK_API_VERSION = process.env.SNYK_API_VERSION ?? "2026-03-25";

if (!SNYK_TOKEN) {
  throw new Error("SNYK_TOKEN is required");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function encodePurl(purl: string): string {
  return encodeURIComponent(purl);
}

function looksLikeUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function buildPurl(packageType: string, packageName: string, packageVersion: string): string {
  return `pkg:${packageType}/${packageName}@${packageVersion}`;
}

function requireRestIssueUuid(toolName: string, issueId: string) {
  if (looksLikeUuid(issueId)) return;

  throw new Error(
    `${toolName} requires a REST API issue UUID. ` +
      "For project-scoped vulnerability identifiers like SNYK-JS-..., use " +
      "snyk_get_project_issue_analysis or snyk_get_project_issue_paths.",
  );
}

async function resolveProjectIssueIds(
  orgId: string,
  projectId: string,
  issueId: string,
  apiVersion: string,
) {
  let restIssue: any = null;
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
      limit: "100",
      "scan_item.type": "project",
      "scan_item.id": projectId,
    });
    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
    );
    const items = Array.isArray(data?.data) ? data.data : [];
    const match = items.find((item: any) => item?.attributes?.key === issueId);
    restIssue = match ? summarizeIssueV3(match) : null;
  }

  return {
    restIssue,
    restIssueId: restIssue?.id ?? (looksLikeUuid(issueId) ? issueId : null),
    v1IssueId,
  };
}

function derivePurl(
  packageType: string,
  purl?: string,
  packageName?: string,
  packageVersion?: string,
) {
  if (purl) return purl;
  if (packageName && packageVersion) {
    return buildPurl(packageType, packageName, packageVersion);
  }
  return null;
}

function requirePurlInput(
  packageType: string,
  purl?: string,
  packageName?: string,
  packageVersion?: string,
) {
  const resolvedPurl = derivePurl(packageType, purl, packageName, packageVersion);

  if (resolvedPurl) return resolvedPurl;

  throw new Error(
    "Provide either purl or the combination packageType/packageName/packageVersion.",
  );
}

function normalizeVersion(version: unknown): string | null {
  if (typeof version !== "string") return null;
  const trimmed = version.trim();
  if (!trimmed || trimmed === "undefined") return null;
  return trimmed;
}

function formatPackageLabel(name: unknown, version: unknown): string {
  const resolvedName = typeof name === "string" && name.trim() ? name : "unknown";
  const resolvedVersion = normalizeVersion(version);
  return resolvedVersion ? `${resolvedName}@${resolvedVersion}` : resolvedName;
}

function normalizePathNode(node: any) {
  return {
    name: node?.name ?? "unknown",
    version: normalizeVersion(node?.version),
    fixVersion: normalizeVersion(node?.fixVersion),
  };
}

function parsePackageFixVersions(description?: string | null): string[] {
  if (!description) return [];

  const remediationMatch = description.match(/Upgrade `[^`]+` to version (.+?) or higher\./is);
  if (!remediationMatch?.[1]) return [];

  return remediationMatch[1]
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function selectRelevantFixVersion(currentVersion: string | null, fixVersions: string[]): string | null {
  if (!fixVersions.length) return null;

  const currentMajor = currentVersion?.match(/^(\d+)\./)?.[1] ?? null;
  if (!currentMajor) return fixVersions[0] ?? null;

  const sameMajor = fixVersions.find((version) => version.startsWith(`${currentMajor}.`));
  return sameMajor ?? fixVersions[0] ?? null;
}

function summarizeIssuePath(path: any[]) {
  const nodes = (Array.isArray(path) ? path : []).map(normalizePathNode);
  const first = nodes[0] ?? null;
  const last = nodes[nodes.length - 1] ?? null;
  const pathString = nodes
    .map((node: any) => formatPackageLabel(node?.name, node?.version))
    .join(" › ");

  let remediation: string | null = null;
  if (first?.fixVersion) {
    remediation = first.fixVersion === first.version
      ? `Re-lock transitive dependencies; direct dependency ${first.name}@${first.version} is already at the fixable parent version ${first.fixVersion}.`
      : `Upgrade direct dependency ${first.name} from ${first.version ?? "unknown"} to ${first.fixVersion}.`;
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
    remediation: remediation ?? "No remediation path available.",
  };
}

async function snykGet(path: string, accept = "application/vnd.api+json") {
  const url = `${SNYK_API_BASE}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `token ${SNYK_TOKEN}`,
        Accept: accept,
        "Content-Type": accept,
      },
    });
  } catch (cause) {
    throw new Error(`Snyk API network error\nURL: ${url}`, { cause });
  }

  const text = await response.text();

  if (!response.ok) {
    throw new Error(
      `Snyk API error ${response.status} ${response.statusText}\nURL: ${url}\nResponse: ${text}`,
    );
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Summarize a Snyk REST API issue object (v3 /rest/orgs/{orgId}/issues). */
function summarizeIssueV3(item: any) {
  const attrs = item?.attributes ?? {};

  // Coordinates (Snyk Code issues)
  const coordinates = Array.isArray(attrs.coordinates)
    ? attrs.coordinates.map((c: any) => {
        const reps = Array.isArray(c.representations)
          ? c.representations.map((r: any) => ({
              file: r?.sourceLocation?.file,
              commitId: r?.sourceLocation?.commit_id,
              region: r?.sourceLocation?.region,
            }))
          : [];
        return {
          state: c.state,
          createdAt: c.created_at,
          resolvedAt: c.last_resolved_at,
          isFixableManually: c.is_fixable_manually,
          isFixableSnyk: c.is_fixable_snyk,
          isFixableUpstream: c.is_fixable_upstream,
          representations: reps,
        };
      })
    : [];

  // Risk score
  const risk = attrs.risk ?? {};
  const classes = Array.isArray(attrs.classes)
    ? attrs.classes.map((c: any) => ({ id: c.id, type: c.type, source: c.source }))
    : [];
  const problems = Array.isArray(attrs.problems)
    ? attrs.problems.map((p: any) => ({ id: p.id, type: p.type, source: p.source }))
    : [];

  return {
    id: item?.id,
    key: attrs.key,
    title: attrs.title,
    description: attrs.description,
    type: attrs.type, // "code" or "package"
    effectiveSeverityLevel: attrs.effective_severity_level,
    status: attrs.status,
    ignored: attrs.ignored,
    createdAt: attrs.created_at,
    updatedAt: attrs.updated_at,
    classes,
    problems,
    coordinates,
    risk: {
      score: risk?.score?.value,
      model: risk?.score?.model,
      factors: risk?.factors,
    },
    resolution: attrs.resolution,
    scanItemId: item?.relationships?.scan_item?.data?.id,
    organizationId: item?.relationships?.organization?.data?.id,
  };
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "snyk-api-mcp",
  version: "0.2.0",
});

// ---------------------------------------------------------------------------
// Tool: snyk_onboarding
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_onboarding",
  {
    description:
      "Get an overview of all available Snyk tools, their recommended workflow, " +
      "and best practices. Call this first when onboarding to understand how to use the server.",
    inputSchema: {},
  },
  async () => {
    const guide = {
      server: "snyk-api-mcp v0.2.0",
      description:
        "Snyk REST API bridge — find repositories, projects, and security vulnerabilities.",
      identifierRules: {
        orgId: "Always the Snyk organization UUID, never an org display name or slug.",
        projectId: "Always the Snyk project UUID, never a project name, repo name, or display name.",
      },
      recommendedWorkflow: [
        {
          step: 1,
          tool: "snyk_resolve_org_id",
          input: "orgSlug (e.g. 'my-snyk-org')",
          output: "orgId (UUID)",
          note: "You can also use the org UUID directly if you already know it.",
        },
        {
          step: 2,
          tool: "snyk_get_targets",
          input: "orgId, optional displayName (e.g. 'my-org/my-repo')",
          output: "target(s) with id, url, origin",
          note: "A target is a GitHub repo, container image, etc. orgId must be the org UUID.",
        },
        {
          step: 3,
          tool: "snyk_get_projects",
          input: "orgId, optional targetId",
          output: "projects with id, name, type (pnpm/dockerfile/sast), status",
          note:
            "A target can have multiple projects (e.g. each package.json is a separate pnpm project). Use the returned project id as projectId in later calls.",
        },
        {
          step: 4,
          tool: "snyk_get_project_issues",
          input: "orgId, projectId, optional severity/status/issueType/limit",
          output: "issues list with id, title, CVE, risk score, status",
          note:
            "Use severity='critical' and status='open' to find the most urgent issues. projectId must be the Snyk project UUID returned by snyk_get_projects.",
        },
      ],
      additionalTools: [
        {
          tool: "snyk_list_org_issues",
          description:
            "Search all issues across the entire org. Supports titleSearch for keyword matching.",
        },
        {
          tool: "snyk_get_issue_detail",
          description:
            "Get full detail for a single issue (by REST API UUID, not the web UI fragment ID).",
        },
        {
          tool: "snyk_get_package_issue_description",
          description:
            "Look up all known vulnerabilities for a package by PURL (e.g. pkg:npm/axios@1.7.0).",
        },
        {
          tool: "snyk_get_project_issue_paths",
          description:
            "Get the data flow path for a vulnerability in a project (v1 API).",
        },
      ],
      tips: [
        "Always resolve the org ID first — most tools require it.",
        "When a tool asks for orgId or projectId, pass the Snyk UUID returned by earlier tools, not a display name.",
        "Filter issues by severity+status to reduce noise (e.g. severity='critical', status='open').",
        "The same vulnerability (same Snyk key) may appear in multiple projects — that's expected.",
        "Use snyk_get_projects with targetId to efficiently list all projects for one repo.",
      ],
    };

    return {
      content: [{ type: "text", text: JSON.stringify(guide, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_resolve_org_id
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_resolve_org_id",
  {
    description:
      "Resolve a Snyk organization slug (e.g. 'my-snyk-org') or partial name to its UUID. " +
      "Use this before calling tools that require an orgId when you only have a human-readable org name.",
    inputSchema: {
      orgSlug: z
        .string()
        .describe(
          "Organization slug or partial name, e.g. 'my-snyk-org' or 'my-org'",
        ),
    },
  },
  async ({ orgSlug }) => {
    const data = await snykGet(
      `/rest/orgs?version=${encodeURIComponent(SNYK_API_VERSION)}&limit=100`,
    );
    const orgs = Array.isArray(data?.data) ? data.data : [];
    const lower = orgSlug.toLowerCase();

    const matches = orgs
      .filter((org: any) => {
        const slug: string = org?.attributes?.slug ?? "";
        const name: string = org?.attributes?.name ?? "";
        return (
          slug.toLowerCase().includes(lower) ||
          name.toLowerCase().includes(lower)
        );
      })
      .map((org: any) => ({
        id: org.id,
        slug: org?.attributes?.slug,
        name: org?.attributes?.name,
        groupName: org?.attributes?.group?.name,
      }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { query: orgSlug, matchCount: matches.length, matches },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_projects
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_projects",
  {
    description:
      "List all Snyk projects for an organization, optionally filtered by target_id. " +
      "Use this after snyk_get_targets to get full project details (id, name, type, origin, status) " +
      "for a specific target/repository.",
    inputSchema: {
      orgId: z
        .string()
        .describe(
          "Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.",
        ),
      targetId: z
        .string()
        .optional()
        .describe(
          "Filter projects by target ID (UUID). Use snyk_get_targets first to find the target ID for a repository.",
        ),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2026-03-25"),
    },
  },
  async ({ orgId, targetId, version }) => {
    const apiVersion = version || SNYK_API_VERSION;

    const params = new URLSearchParams({
      version: apiVersion,
      limit: "100",
    });
    if (targetId) params.set("target_id", targetId);

    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/projects?${params.toString()}`,
    );

    const projects = (Array.isArray(data?.data) ? data.data : []).map(
      (p: any) => ({
        id: p.id,
        name: p?.attributes?.name,
        type: p?.attributes?.type,
        origin: p?.attributes?.origin,
        status: p?.attributes?.status,
        created: p?.attributes?.created,
        targetId: p?.relationships?.target?.data?.id,
      }),
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              query: { orgId, targetId, apiVersion },
              matchCount: projects.length,
              projects,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_targets
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_targets",
  {
    description:
      "List Snyk targets (repositories/containers) for an organization, " +
      "optionally filtered by display name. " +
      "Use snyk_get_projects to list all projects for a specific target.",
    inputSchema: {
      orgId: z
        .string()
        .describe(
          "Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.",
        ),
      displayName: z
        .string()
        .optional()
        .describe(
          "Filter targets by display name (URL-encoded). " +
            "E.g. 'my-github-org/my-repo' for the target with that display name.",
        ),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2026-03-25"),
    },
  },
  async ({ orgId, displayName, version }) => {
    const apiVersion = version || SNYK_API_VERSION;

    const params = new URLSearchParams({
      version: apiVersion,
      limit: "100",
    });
    if (displayName) params.set("display_name", displayName);

    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/targets?${params.toString()}`,
    );

    const targets = (Array.isArray(data?.data) ? data.data : []).map(
      (t: any) => ({
        id: t.id,
        displayName: t?.attributes?.display_name,
        url: t?.attributes?.url,
        origin: t?.attributes?.origin,
        isPrivate: t?.attributes?.is_private,
        createdDate: t?.attributes?.created_date,
      }),
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              query: { orgId, displayName, apiVersion },
              matchCount: targets.length,
              targets,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_project_issues
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_project_issues",
  {
    description:
      "List all Snyk issues for a specific project (by project ID). " +
      "Supports filtering by type ('code' or 'package'), severity, and status. " +
      "Use snyk_get_targets and snyk_get_projects first to find the project ID for a given repository.",
    inputSchema: {
      orgId: z
        .string()
        .describe(
          "Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.",
        ),
      projectId: z
        .string()
        .describe(
          "Snyk project ID (UUID). Use snyk_get_targets to discover project IDs for a target.",
        ),
      issueType: z
        .enum(["code", "package", "all"])
        .optional()
        .default("all")
        .describe("Filter by issue type: 'code' (Snyk Code), 'package' (open source), or 'all'."),
      severity: z
        .enum(["low", "medium", "high", "critical"])
        .optional()
        .describe("Filter by effective severity level."),
      status: z
        .enum(["open", "resolved", "ignored"])
        .optional()
        .describe("Filter by issue status."),
      limit: z
        .number()
        .optional()
        .default(100)
        .describe("Max results to return (1-100)."),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2026-03-25"),
    },
  },
  async ({ orgId, projectId, issueType, severity, status, limit, version }) => {
    const apiVersion = version || SNYK_API_VERSION;
    const API_PAGE_SIZE = 100;

    const params = new URLSearchParams({
      version: apiVersion,
      limit: String(API_PAGE_SIZE),
      "scan_item.type": "project",
      "scan_item.id": projectId,
    });

    let snykType: string | undefined;
    if (issueType === "code") snykType = "code";
    else if (issueType === "package") snykType = "package";

    if (snykType) params.set("type", snykType);
    if (severity) params.set("effective_severity_level", severity);
    if (status) params.set("status", status);

    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
    );

    let items = Array.isArray(data?.data) ? data.data : [];
    items = items.slice(0, limit);

    const result = {
      query: { orgId, projectId, issueType, severity, status, limit, apiVersion },
      matchCount: items.length,
      issues: items.map(summarizeIssueV3),
    };

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_list_org_issues
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_list_org_issues",
  {
    description:
      "List issues for a Snyk organization. Supports filtering by type ('code' or 'package'), " +
      "severity, status, and free-text title search. Use this to find Snyk Code issues (type=code) " +
      "or to discover issues when you only have a title keyword (e.g. 'Hardcoded Secret').",
    inputSchema: {
      orgId: z
        .string()
        .describe(
          "Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.",
        ),
      issueType: z
        .enum(["code", "package", "all"])
        .optional()
        .default("all")
        .describe("Filter by issue type: 'code' (Snyk Code), 'package' (open source), or 'all'."),
      severity: z
        .enum(["low", "medium", "high", "critical"])
        .optional()
        .describe("Filter by effective severity level."),
      status: z
        .enum(["open", "resolved", "ignored"])
        .optional()
        .describe("Filter by issue status."),
      titleSearch: z
        .string()
        .optional()
        .describe(
          "Free-text search on issue title (client-side substring match). Case-insensitive.",
        ),
      limit: z
        .number()
        .optional()
        .default(100)
        .describe("Max results to return (1-100)."),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2024-10-15"),
    },
  },
  async ({ orgId, issueType, severity, status, titleSearch, limit, version }) => {
    const apiVersion = version || SNYK_API_VERSION;

    // Snyk REST API only accepts specific limit values (e.g. 10, 100).
    // Always fetch the maximum and then client-side truncate.
    const API_PAGE_SIZE = 100;

    // Build query params
    const params = new URLSearchParams({
      version: apiVersion,
      limit: String(API_PAGE_SIZE),
    });

    // Map type filter
    let snykType: string | undefined;
    if (issueType === "code") snykType = "code";
    else if (issueType === "package") snykType = "package";

    if (snykType) params.set("type", snykType);
    if (severity) params.set("effective_severity_level", severity);
    if (status) params.set("status", status);

    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues?${params.toString()}`,
    );

    let items = Array.isArray(data?.data) ? data.data : [];

    // Client-side title search
    if (titleSearch) {
      const lower = titleSearch.toLowerCase();
      items = items.filter((item: any) => {
        const title: string = item?.attributes?.title ?? "";
        const description: string = item?.attributes?.description ?? "";
        return title.toLowerCase().includes(lower) || description.toLowerCase().includes(lower);
      });
    }

    // Limit
    items = items.slice(0, limit);

    const result = {
      query: { orgId, issueType, severity, status, titleSearch, limit, apiVersion },
      matchCount: items.length,
      issues: items.map(summarizeIssueV3),
    };

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_issue_detail
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_issue_detail",
  {
    description:
      "Get full details of a single Snyk issue by its REST API issue ID " +
      "(e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'). " +
      "Use snyk_list_org_issues first to discover the issue ID from a title keyword. " +
      "NOTE: The fragment ID from a Snyk web UI URL (like '#issue-2f30d999-...') is NOT " +
      "a REST API issue ID — you must find the real ID via snyk_list_org_issues.",
    inputSchema: {
      orgId: z
        .string()
        .describe(
          "Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.",
        ),
      issueId: z
        .string()
        .describe(
          "Snyk REST API issue ID (UUID), e.g. '61b1f9fa-0bfc-469e-93e6-ea31a53e7412'. " +
            "NOT the fragment from a web UI URL.",
        ),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2024-10-15"),
    },
  },
  async ({ orgId, issueId, version }) => {
    const apiVersion = version || SNYK_API_VERSION;

    requireRestIssueUuid("snyk_get_issue_detail", issueId);

    const data = await snykGet(
      `/rest/orgs/${encodeURIComponent(orgId)}/issues/${encodeURIComponent(issueId)}?version=${encodeURIComponent(apiVersion)}`,
    );

    const result = {
      query: { orgId, issueId, apiVersion },
      issue: data?.data ? summarizeIssueV3(data.data) : null,
      raw: data,
    };

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_project_issue_analysis
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_project_issue_analysis",
  {
    description:
      "Compose a UI-like analysis for a single open source issue in a specific project. " +
      "Combines REST issue-instance metadata, v1 dependency paths, and package vulnerability metadata " +
      "so agents can access introduced-through parents, the relevant vulnerable-package fix version, " +
      "a project remediation hint, and detailed dependency paths in one response.",
    inputSchema: {
      orgId: z
        .string()
        .describe("Snyk Organization ID."),
      projectId: z
        .string()
        .describe("Snyk Project ID in which the issue appears."),
      issueId: z
        .string()
        .describe(
          "Issue identifier. Prefer the v1 vulnerability ID (for example SNYK-JS-ESBUILD-17750822). REST UUID issue IDs are also accepted.",
        ),
      packageType: z
        .string()
        .optional()
        .default("npm")
        .describe("Package ecosystem for constructing a PURL when package metadata is derived from paths. Example: npm."),
      packageName: z
        .string()
        .optional()
        .describe("Optional package name override if it cannot be derived from the dependency path."),
      packageVersion: z
        .string()
        .optional()
        .describe("Optional package version override if it cannot be derived from the dependency path."),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version, e.g. 2026-03-25"),
      perPage: z
        .number()
        .optional()
        .default(1000)
        .describe("How many project issue paths to request from v1 (max 1000)."),
    },
  },
  async ({ orgId, projectId, issueId, packageType, packageName, packageVersion, version, perPage }) => {
    const apiVersion = version || SNYK_API_VERSION;
    const { restIssue, restIssueId, v1IssueId } = await resolveProjectIssueIds(
      orgId,
      projectId,
      issueId,
      apiVersion,
    );

    const pathData = await snykGet(
      `/v1/org/${encodeURIComponent(orgId)}` +
        `/project/${encodeURIComponent(projectId)}` +
        `/issue/${encodeURIComponent(v1IssueId)}` +
        `/paths?perPage=${encodeURIComponent(String(perPage))}&page=1`,
      "application/json",
    );

    const rawPaths = Array.isArray(pathData?.paths) ? pathData.paths : [];
    const pathSummaries = rawPaths.map(summarizeIssuePath);
    const shortestPath = pathSummaries[0] ?? null;

    const derivedPackageName = packageName ?? shortestPath?.vulnerablePackage?.name ?? null;
    const derivedPackageVersion = packageVersion ?? shortestPath?.vulnerablePackage?.version ?? null;
    const purl = derivePurl(
      packageType,
      undefined,
      derivedPackageName ?? undefined,
      derivedPackageVersion ?? undefined,
    );

    let packageIssue: any = null;
    if (purl) {
      const pkgData = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/packages/${encodePurl(purl)}/issues?version=${encodeURIComponent(apiVersion)}&limit=1000`,
      );
      const pkgItems = Array.isArray(pkgData?.data) ? pkgData.data : [];
      const match = pkgItems.find((item: any) => {
        const attrs = item?.attributes ?? {};
        return item?.id === v1IssueId || attrs?.key === v1IssueId;
      });
      packageIssue = match ? summarizeIssueV3(match) : null;
    }

    const remediationFixVersions = parsePackageFixVersions(
      packageIssue?.description ?? restIssue?.description ?? null,
    );
    const selectedPackageFixVersion = selectRelevantFixVersion(
      derivedPackageVersion,
      remediationFixVersions,
    );

    const directDependencies = Array.from(
      new Set(
        pathSummaries
          .map((path: any) => path.directDependency)
          .filter(Boolean)
          .map((dep: any) => formatPackageLabel(dep.name, dep.version)),
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
        severity: restIssue?.effectiveSeverityLevel ?? packageIssue?.effectiveSeverityLevel ?? null,
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
        vulnerableRangeFromDb: packageIssue?.description?.match(/versions\s+(.+?)\n/i)?.[1] ?? null,
      },
      issueContext: {
        introducedThrough: directDependencies,
        remediation: shortestPath?.remediation ?? null,
        exploitMaturity: restIssue?.risk?.factors?.exploitMaturity ?? null,
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
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_package_issue_description (improved)
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_package_issue_description",
  {
    description:
      "Get all Snyk security issues for a package (PURL). " +
      "Returns up to 1000 issues — the allIssues payload can be large. " +
      "Use issueRef to filter to a single issue when possible.",
    inputSchema: {
      orgId: z
        .string()
        .describe("Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug."),
      purl: z
        .string()
        .optional()
        .describe("Package URL, e.g. pkg:npm/lodash@4.17.15"),
      packageType: z
        .string()
        .optional()
        .default("npm")
        .describe("Optional package ecosystem when constructing a PURL from name+version. Example: npm."),
      packageName: z
        .string()
        .optional()
        .describe("Optional package name when you prefer structured package inputs over a raw PURL."),
      packageVersion: z
        .string()
        .optional()
        .describe("Optional package version when you prefer structured package inputs over a raw PURL."),
      issueRef: z
        .string()
        .optional()
        .describe(
          "Optional Snyk issue ID or CVE, e.g. SNYK-JS-LODASH-590103 or CVE-2020-8203",
        ),
      version: z
        .string()
        .optional()
        .describe("Optional Snyk REST API version, e.g. 2024-10-15"),
    },
  },
  async ({ orgId, purl, packageType, packageName, packageVersion, issueRef, version }) => {
    const apiVersion = version || SNYK_API_VERSION;
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
      ? items.find((item: any) => {
          const id = item?.id ?? "";
          const attrs = item?.attributes ?? {};
          const identifiers = [
            id,
            attrs.key,
            ...(attrs.identifiers?.CVE ?? []),
            ...(attrs.identifiers?.CWE ?? []),
            ...(Array.isArray(attrs.problems) ? attrs.problems.map((p: any) => p.id) : []),
          ].filter(Boolean);
          return identifiers.some(
            (v: string) => v.toLowerCase() === issueRef.toLowerCase(),
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
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Tool: snyk_get_project_issue_paths (kept from original)
// ---------------------------------------------------------------------------

server.registerTool(
  "snyk_get_project_issue_paths",
  {
    description:
      "Get the project issue paths for the last Snyk analysis. " +
      "Accepts either a V1 Snyk issue ID (e.g. SNYK-JS-LODASH-590103) or a REST issue UUID and resolves it to the V1 issue ID automatically.",
    inputSchema: {
      orgId: z
        .string()
        .describe("Snyk Organization ID. Use snyk_resolve_org_id if you only have a slug."),
      projectId: z.string().describe("Snyk Project ID"),
      issueId: z
        .string()
        .describe("Snyk vulnerability issue ID (SNYK-...) or REST issue UUID."),
      page: z.number().optional().default(1),
      perPage: z.number().optional().default(1000),
      version: z
        .string()
        .optional()
        .describe("Snyk REST API version used when a REST issue UUID must be resolved to a V1 issue ID."),
    },
  },
  async ({ orgId, projectId, issueId, page, perPage, version }) => {
    const apiVersion = version || SNYK_API_VERSION;
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
      "application/json",
    );

    const result = {
      query: { orgId, projectId, issueId, resolvedRestIssueId: restIssueId, resolvedV1IssueId: v1IssueId, page, perPage, apiVersion },
      snapshotId: data?.snapshotId,
      total: data?.total,
      shortestPath: Array.isArray(data?.paths) ? data.paths[0] : undefined,
      paths: data?.paths,
      links: data?.links,
    };

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);