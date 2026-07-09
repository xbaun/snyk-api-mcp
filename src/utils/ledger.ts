import type { components } from '../snyk/types/snyk-rest.d.ts';
import { normalizeVersion } from './helpers.js';

// ---------------------------------------------------------------------------
// Project classification
// ---------------------------------------------------------------------------

export type ProjectKind = 'package' | 'code' | 'container' | 'unknown';

export interface ProjectClassification {
  projectId: string;
  projectName: string;
  projectType: string;
  kind: ProjectKind;
  workspacePackage: string | null;
}

export type RestIssue = components['schemas']['Issue'];

/**
 * Structural subset of the REST project payload we actually consume.
 *
 * The generated OpenAPI type for `listOrgProjects` currently does not expose
 * the `attributes` object that the live API returns, so we model the minimum
 * compatible shape explicitly and validate it at the boundary.
 */
export interface RestProject {
  id: string;
  attributes: Pick<
    components['schemas']['ProjectAttributes'],
    'name' | 'type' | 'target_file'
  >;
}

/**
 * Snyk package-manager project types that produce dependency-based findings.
 *
 * Source: https://docs.snyk.io/developer-tools/snyk-api/api-endpoints-index-and-tips/project-type-responses-from-the-api
 *
 * Also includes `pnpm`, `uv`, and `cargo` which are shipped by Snyk but not
 * exhaustively listed in that page.
 */
const PACKAGE_MANAGER_TYPES: ReadonlySet<string> = new Set([
  'apk',
  'cargo',
  'cocoapods',
  'composer',
  'conan',
  'cpp',
  'deb',
  'golang',
  'golangdep',
  'gomodules',
  'gradle',
  'govendor',
  'hex',
  'maven',
  'npm',
  'nuget',
  'paket',
  'pip',
  'pipenv',
  'pnpm',
  'poetry',
  'pub',
  'rpm',
  'rubygems',
  'sbt',
  'swift',
  'unmanaged',
  'uv',
  'yarn',
  'yarn-workspace',
]);

const PURL_TYPE_BY_PROJECT_TYPE: Readonly<Record<string, string>> = {
  apk: 'apk',
  cargo: 'cargo',
  cocoapods: 'cocoapods',
  composer: 'composer',
  conan: 'conan',
  deb: 'deb',
  golang: 'golang',
  golangdep: 'golang',
  gomodules: 'golang',
  govendor: 'golang',
  gradle: 'maven',
  hex: 'hex',
  maven: 'maven',
  npm: 'npm',
  nuget: 'nuget',
  pip: 'pypi',
  pipenv: 'pypi',
  pnpm: 'npm',
  poetry: 'pypi',
  pub: 'pub',
  rpm: 'rpm',
  rubygems: 'gem',
  sbt: 'maven',
  swift: 'swift',
  uv: 'pypi',
  yarn: 'npm',
  'yarn-workspace': 'npm',
};

/**
 * Classify a Snyk project into a kind using the API's `type` field.
 *
 * Source: https://docs.snyk.io/developer-tools/snyk-api/api-endpoints-index-and-tips/project-type-responses-from-the-api
 */
export function classifyProject(project: RestProject): ProjectClassification {
  const projectType = (project?.attributes?.type as string) ?? '';
  const name = (project?.attributes?.name as string) ?? '';
  const targetFile = (project?.attributes?.target_file as string) ?? '';
  const workspacePackage =
    deriveWorkspacePackage(targetFile) ??
    deriveWorkspacePackageFromProjectName(name);
  const base: Pick<
    ProjectClassification,
    'projectId' | 'projectName' | 'projectType'
  > = {
    projectId: project.id ?? '',
    projectName: name,
    projectType,
  };

  if (projectType === 'dockerfile') {
    return { ...base, kind: 'container', workspacePackage: null };
  }

  if (projectType === 'sast') {
    return { ...base, kind: 'code', workspacePackage };
  }

  if (PACKAGE_MANAGER_TYPES.has(projectType)) {
    return {
      ...base,
      kind: 'package',
      workspacePackage,
    };
  }

  return { ...base, kind: 'unknown', workspacePackage };
}

// ---------------------------------------------------------------------------
// Advisory grouping
// ---------------------------------------------------------------------------

export interface LedgerIssue {
  advisoryKey: string;
  restIssueId: string;
  issueKey: string;
  issueType: 'package_vulnerability' | 'code';
  severity: string;
  riskScore: number;
  title: string;
  createdAt: string;
  projectId: string;
  projectName: string;
  workspacePackage?: string;
  packageName?: string;
  purl?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
}

export interface LedgerAdvisory {
  advisoryKey: string;
  title: string;
  severity: string;
  issueType: 'package_vulnerability' | 'code';
  issueCount: number;
  affectedProjectCount: number;
  affectedProjectIds: string[];
  affectedWorkspacePackages: string[];
  createdAt: string;
  riskScoreMax: number;
  packageName?: string;
}

const ISSUE_TYPE_ORDER: Readonly<Record<LedgerIssue['issueType'], number>> = {
  package_vulnerability: 0,
  code: 1,
};

const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function compareIssueTypes(
  a: LedgerIssue['issueType'],
  b: LedgerIssue['issueType'],
) {
  return (
    (ISSUE_TYPE_ORDER[a] ?? Number.MAX_SAFE_INTEGER) -
    (ISSUE_TYPE_ORDER[b] ?? Number.MAX_SAFE_INTEGER)
  );
}

function compareSeverities(a: string, b: string) {
  return (
    (SEVERITY_ORDER[a] ?? Number.MAX_SAFE_INTEGER) -
    (SEVERITY_ORDER[b] ?? Number.MAX_SAFE_INTEGER)
  );
}

function compareStringsAsc(a: string | undefined, b: string | undefined) {
  return (a ?? '').localeCompare(b ?? '');
}

function compareNumbersDesc(a: number, b: number) {
  return b - a;
}

function pickHighestSeverity(values: string[]) {
  return [...values].sort(compareSeverities)[0] ?? 'low';
}

export function sortLedgerIssues(issues: LedgerIssue[]): LedgerIssue[] {
  return [...issues].sort((a, b) => {
    return (
      compareIssueTypes(a.issueType, b.issueType) ||
      compareSeverities(a.severity, b.severity) ||
      compareNumbersDesc(a.riskScore, b.riskScore) ||
      compareStringsAsc(a.createdAt, b.createdAt) ||
      compareStringsAsc(a.advisoryKey, b.advisoryKey) ||
      compareStringsAsc(a.projectId, b.projectId) ||
      compareStringsAsc(a.restIssueId, b.restIssueId)
    );
  });
}

export function sortLedgerAdvisories(
  advisories: LedgerAdvisory[],
): LedgerAdvisory[] {
  return [...advisories].sort((a, b) => {
    return (
      compareIssueTypes(a.issueType, b.issueType) ||
      compareSeverities(a.severity, b.severity) ||
      compareNumbersDesc(a.riskScoreMax, b.riskScoreMax) ||
      compareNumbersDesc(a.affectedProjectCount, b.affectedProjectCount) ||
      compareNumbersDesc(a.issueCount, b.issueCount) ||
      compareStringsAsc(a.createdAt, b.createdAt) ||
      compareStringsAsc(a.advisoryKey, b.advisoryKey)
    );
  });
}

export function groupIssuesToAdvisories(
  issues: LedgerIssue[],
): LedgerAdvisory[] {
  const advisoryMap = new Map<string, LedgerIssue[]>();

  for (const issue of issues) {
    const existing = advisoryMap.get(issue.advisoryKey);
    if (existing) {
      existing.push(issue);
    } else {
      advisoryMap.set(issue.advisoryKey, [issue]);
    }
  }

  const advisories: LedgerAdvisory[] = [];
  for (const [, group] of advisoryMap) {
    if (group.length === 0) continue;
    const first = group[0]!;
    const affectedProjectIds = [...new Set(group.map((i) => i.projectId))];
    const affectedWorkspacePackages = [
      ...new Set(
        group
          .map((i) => i.workspacePackage)
          .filter((value): value is string => Boolean(value)),
      ),
    ];
    const riskScores = group.map((i) => i.riskScore);
    const createdAt =
      group
        .map((i) => i.createdAt)
        .filter(Boolean)
        .sort()[0] ?? '';
    const packageName =
      group.find((issue) => issue.issueType === 'package_vulnerability')
        ?.packageName ?? undefined;

    advisories.push({
      advisoryKey: first.advisoryKey,
      title: first.title,
      severity: pickHighestSeverity(group.map((issue) => issue.severity)),
      issueType: first.issueType,
      issueCount: group.length,
      affectedProjectCount: affectedProjectIds.length,
      affectedProjectIds,
      affectedWorkspacePackages,
      createdAt,
      riskScoreMax: Math.max(...riskScores),
      ...(packageName ? { packageName } : {}),
    });
  }

  return sortLedgerAdvisories(advisories);
}

export function dedupeLedgerIssues(issues: LedgerIssue[]): LedgerIssue[] {
  const uniqueIssues = new Map<string, LedgerIssue>();

  for (const issue of issues) {
    const key = `${issue.projectId}:${issue.advisoryKey}:${issue.restIssueId}`;
    if (!uniqueIssues.has(key)) {
      uniqueIssues.set(key, issue);
    }
  }

  return [...uniqueIssues.values()];
}

// ---------------------------------------------------------------------------
// Package data extraction
// ---------------------------------------------------------------------------

export function extractPackageIdentityFromIssue(
  item: RestIssue,
  projectType: string,
): Pick<LedgerIssue, 'packageName' | 'purl'> {
  const coordinates = item.attributes.coordinates ?? [];

  for (const coord of coordinates) {
    const reps = coord.representations ?? [];
    for (const rep of reps) {
      if (!('dependency' in rep)) continue;

      const packageName = rep.dependency.package_name ?? undefined;
      const packageVersion = normalizeVersion(rep.dependency.package_version);
      const purl = buildPackagePurl(projectType, packageName, packageVersion);

      return {
        ...(packageName ? { packageName } : {}),
        ...(purl ? { purl } : {}),
      };
    }
  }

  return {};
}

// ---------------------------------------------------------------------------
// Code data extraction
// ---------------------------------------------------------------------------

export function extractCodeLocationFromIssue(
  item: RestIssue,
): Pick<LedgerIssue, 'filePath' | 'startLine' | 'endLine'> {
  const coordinates = item.attributes.coordinates ?? [];

  for (const coord of coordinates) {
    const reps = coord.representations ?? [];
    for (const rep of reps) {
      if ('sourceLocation' in rep) {
        const loc = rep.sourceLocation;
        return {
          filePath: loc.file,
          ...(typeof loc.region?.start.line === 'number'
            ? { startLine: loc.region.start.line }
            : {}),
          ...(typeof loc.region?.end.line === 'number'
            ? { endLine: loc.region.end.line }
            : {}),
        };
      }
    }
  }

  return {};
}

// ---------------------------------------------------------------------------
// Finding type derivation
// ---------------------------------------------------------------------------

export function toLedgerIssueType(
  issueType: RestIssue['attributes']['type'],
): 'package_vulnerability' | 'code' {
  if (issueType === 'package_vulnerability') return 'package_vulnerability';
  if (issueType === 'code') return 'code';

  throw new Error(
    `Unsupported issue type '${issueType}' for ledger mapping. Expected 'package_vulnerability' or 'code'.`,
  );
}

// ---------------------------------------------------------------------------
// Safe numeric extraction
// ---------------------------------------------------------------------------

export function extractRiskScore(item: RestIssue): number {
  return item.attributes.risk?.score?.value ?? 0;
}

function buildPackagePurl(
  projectType: string,
  packageName: string | undefined,
  packageVersion: string | null,
) {
  if (!packageName || !packageVersion) return undefined;

  const purlType = PURL_TYPE_BY_PROJECT_TYPE[projectType];
  if (!purlType) return undefined;

  if (purlType === 'maven' && packageName.includes(':')) {
    const [groupId, artifactId] = packageName.split(':', 2);
    if (groupId && artifactId) {
      return `pkg:${purlType}/${groupId}/${artifactId}@${packageVersion}`;
    }
  }

  return `pkg:${purlType}/${packageName}@${packageVersion}`;
}

/**
 * Extract a workspace-relative directory path from a Snyk `target_file`.
 *
 * "path/to/package.json" → "path/to"
 * "" or root-level file   → null
 */
export function deriveWorkspacePackage(targetFile: string): string | null {
  const lastSlash = targetFile.lastIndexOf('/');
  return lastSlash >= 0 ? targetFile.substring(0, lastSlash) : null;
}

export function deriveWorkspacePackageFromProjectName(
  projectName: string,
): string | null {
  const candidate = projectName.includes(':')
    ? (projectName.split(':').pop() ?? '')
    : projectName;

  return deriveWorkspacePackage(candidate);
}
