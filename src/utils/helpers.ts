// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type SnykItem = {
  id: string;
  attributes: Record<string, unknown>;
  relationships?: Record<string, { data?: { id?: string; type?: string } }>;
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

export type CoordinateSummary = {
  state?: unknown;
  createdAt?: unknown;
  resolvedAt?: unknown;
  isFixableManually?: unknown;
  isFixableSnyk?: unknown;
  isFixableUpstream?: unknown;
  remedies: Array<Record<string, unknown>>;
  representations: Array<Record<string, unknown>>;
};

export type IssueSummary = {
  id: string;
  key?: string;
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
  risk: { score?: unknown; model?: unknown; factors?: unknown };
  resolution?: unknown;
  scanItemId?: string;
  organizationId?: string;
};

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export function looksLikeUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

export function requireRestIssueUuid(toolName: string, issueId: string) {
  if (looksLikeUuid(issueId)) return;

  throw new Error(
    `${toolName} requires a REST API issue UUID. ` +
      'For project-scoped vulnerability identifiers like SNYK-JS-..., use ' +
      'snyk_get_project_issue_analysis or snyk_get_project_issue_paths.',
  );
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
