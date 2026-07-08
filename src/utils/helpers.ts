// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

type SnykRelationshipNode = {
  id?: string | null;
  type?: string | null;
  [key: string]: unknown;
};

export type SnykItem = {
  id?: string;
  type?: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<
    string,
    {
      data?: SnykRelationshipNode | SnykRelationshipNode[];
    } | null
  >;
  meta?: Record<string, unknown>;
};

export type SnykPathNode = Record<string, unknown>;

export type NormalizedPathNode = {
  name: string;
  version: string | null;
  fixVersion: string | null;
};

export type PathSummary = {
  directDependency: NormalizedPathNode | null;
  vulnerablePackage: { name: string; version: string | null } | null;
  pathLength: number;
  path: NormalizedPathNode[];
  pathString: string;
  remediation: string;
};

export type IssueRegionSummary = {
  start?: { line: number; column: number };
  end?: { line: number; column: number };
};

export type IssueRepresentationSummary = {
  id?: string;
  type?: string;
  identity?: string;
  packageName?: string;
  packageVersion?: string | null;
  purl?: string | null;
  file?: string;
  commitId?: string;
  region?: IssueRegionSummary;
  resourcePath?: string;
};

export type IssueRemedySummary = {
  type?: string;
  description?: string;
  details: {
    upgradePackage: string[];
    fixedIn?: string[];
    schemaVersion?: string;
  };
};

export type IssueRiskSummary = {
  score?: number;
  model?: string;
  factors?: unknown;
  exploitMaturityLevels?: Array<{ format: string; level: string }>;
};

export type CoordinateSummary = {
  state?: 'open' | 'resolved';
  createdAt?: string;
  resolvedAt?: string;
  isFixableManually?: boolean;
  isFixableSnyk?: boolean;
  isFixableUpstream?: boolean;
  remedies: IssueRemedySummary[];
  representations: IssueRepresentationSummary[];
};

type IssueSummaryBase = {
  issueKey?: string;
  title?: string;
  description?: string;
  type?: string;
  effectiveSeverityLevel?: string;
  status?: string;
  ignored?: boolean;
  createdAt?: string;
  updatedAt?: string;
  classes: Array<{ id?: string; type?: string; source?: string }>;
  problems: Array<{ id?: string; type?: string; source?: string }>;
  coordinates: CoordinateSummary[];
  risk: IssueRiskSummary;
  resolution?: unknown;
};

export type RestIssueSummary = IssueSummaryBase & {
  restIssueId: string;
  scanItemId?: string;
  organizationId?: string;
};

export type PackageVulnerabilitySummary = IssueSummaryBase & {
  vulnerabilityId: string;
};

export type NormalizedIssueSummary =
  RestIssueSummary | PackageVulnerabilitySummary;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export function looksLikeUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

/**
 * Parse the `starting_after` cursor out of a Snyk REST response `links` object.
 *
 * Snyk returns `links.next` as either a full URL string like:
 *   …?…&starting_after=v1.eyJpZCI6IjEwMDAifQo=
 * or as a `LinkProperty` object `{ href: "…", meta: {…} }`.
 *
 * We extract only the opaque cursor value so the caller can pass it back as
 * `startingAfter` on the next request.
 */
export function extractNextCursor(
  links: { next?: unknown } | null | undefined,
): string | null {
  if (!links) return null;

  const nextRaw = links.next;
  if (!nextRaw) return null;

  const href: string | null =
    typeof nextRaw === 'string'
      ? nextRaw
      : typeof nextRaw === 'object' &&
          (nextRaw as Record<string, unknown>)?.href != null
        ? String((nextRaw as Record<string, unknown>).href)
        : null;

  if (!href) return null;

  // Snyk returns relative URLs like /rest/orgs/...?starting_after=...
  // Extract just the query string and parse with URLSearchParams directly.
  const queryStart = href.indexOf('?');
  if (queryStart === -1) return null;
  return new URLSearchParams(href.slice(queryStart)).get('starting_after');
}

export function requireUuid(fieldName: string, value: string) {
  if (looksLikeUuid(value)) return;

  throw new Error(`'${fieldName}' must be a UUID. Got: '${value}'.`);
}

export function requireRestIssueUuid(toolName: string, restIssueId: string) {
  requireUuid('restIssueId', restIssueId);
}

export function normalizeVersion(version: unknown): string | null {
  if (typeof version !== 'string') return null;
  const trimmed = version.trim();
  if (!trimmed || trimmed === 'undefined') return null;
  return trimmed;
}

export function formatPackageLabel(name: unknown, version: unknown): string {
  const resolvedName =
    typeof name === 'string' && name.trim() ? name : 'unknown';
  const resolvedVersion = normalizeVersion(version);
  return resolvedVersion ? `${resolvedName}@${resolvedVersion}` : resolvedName;
}

export function normalizePathNode(node: SnykPathNode): NormalizedPathNode {
  const rawName = node?.name;
  return {
    name: typeof rawName === 'string' && rawName.trim() ? rawName : 'unknown',
    version: normalizeVersion(node?.version),
    fixVersion: normalizeVersion(node?.fixVersion),
  };
}

export function uniqueStrings(
  values: Array<string | null | undefined>,
): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (typeof value === 'string' ? value.trim() : null))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}

export function parseUpgradePackageValue(value: unknown): string[] {
  if (typeof value === 'string') {
    return uniqueStrings(value.split(',').map((part) => part.trim()));
  }

  if (Array.isArray(value)) {
    return uniqueStrings(
      value.map((entry) => (typeof entry === 'string' ? entry : null)),
    );
  }

  return [];
}

export function parsePackageFixVersions(description?: string | null): string[] {
  if (!description) return [];

  const remediationMatch = description.match(
    /Upgrade `[^`]+` to version (.+?) or higher\./is,
  );
  if (!remediationMatch?.[1]) return [];

  return remediationMatch[1]
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

export function selectRelevantFixVersion(
  currentVersion: string | null,
  fixVersions: string[],
): string | null {
  if (!fixVersions.length) return null;

  const currentMajor = currentVersion?.match(/^(\d+)\./)?.[1] ?? null;
  if (!currentMajor) return fixVersions[0] ?? null;

  const sameMajor = fixVersions.find((version) =>
    version.startsWith(`${currentMajor}.`),
  );
  return sameMajor ?? fixVersions[0] ?? null;
}
