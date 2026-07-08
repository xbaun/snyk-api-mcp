import type { components } from '../snyk/types/snyk-rest.d.ts';
import { normalizeVersion, parseUpgradePackageValue } from './helpers.js';

// ---------------------------------------------------------------------------
// Project classification
// ---------------------------------------------------------------------------

export type ProjectKind = 'package' | 'code' | 'container' | 'unknown';

export interface ProjectClassification {
  projectId: string;
  projectName: string;
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

/**
 * Classify a Snyk project into a kind using the API's `type` field.
 *
 * Source: https://docs.snyk.io/developer-tools/snyk-api/api-endpoints-index-and-tips/project-type-responses-from-the-api
 */
export function classifyProject(project: RestProject): ProjectClassification {
  const projectType = (project?.attributes?.type as string) ?? '';
  const name = (project?.attributes?.name as string) ?? '';
  const targetFile = (project?.attributes?.target_file as string) ?? '';
  const base: Pick<ProjectClassification, 'projectId' | 'projectName'> = {
    projectId: project.id ?? '',
    projectName: name,
  };

  if (projectType === 'dockerfile') {
    return { ...base, kind: 'container', workspacePackage: null };
  }

  if (projectType === 'sast') {
    return { ...base, kind: 'code', workspacePackage: null };
  }

  if (PACKAGE_MANAGER_TYPES.has(projectType)) {
    return {
      ...base,
      kind: 'package',
      workspacePackage: deriveWorkspacePackage(targetFile),
    };
  }

  return { ...base, kind: 'unknown', workspacePackage: null };
}

// ---------------------------------------------------------------------------
// Advisory grouping
// ---------------------------------------------------------------------------

export interface LedgerIssue {
  advisoryKey: string;
  restIssueId: string;
  issueKey: string;
  vulnerabilityId?: string;
  issueType: 'package_vulnerability' | 'code';
  severity: string;
  riskScore: number;
  title: string;
  createdAt: string;
  status: string;
  projectId: string;
  projectName: string;
  workspacePackage: string | null;
  targetId: string;
  package: {
    name: string | null;
    version: string | null;
    purl: string | null;
    fixVersions: string[];
  };
  code: {
    file: string | null;
    startLine: number | null;
    endLine: number | null;
    commitId: string | null;
  } | null;
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
  packageHint: string | null;
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
          .filter((p): p is string => Boolean(p)),
      ),
    ];
    const riskScores = group.map((i) => i.riskScore);
    const createdAt =
      group
        .map((i) => i.createdAt)
        .filter(Boolean)
        .sort()[0] ?? '';

    advisories.push({
      advisoryKey: first.advisoryKey,
      title: first.title,
      severity: first.severity,
      issueType: first.issueType,
      issueCount: group.length,
      affectedProjectCount: affectedProjectIds.length,
      affectedProjectIds,
      affectedWorkspacePackages,
      createdAt,
      riskScoreMax: Math.max(...riskScores),
      packageHint: first.package.name ?? null,
    });
  }

  return advisories.sort((a, b) => b.riskScoreMax - a.riskScoreMax);
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

export function extractPackageDataFromIssue(
  item: RestIssue,
): LedgerIssue['package'] {
  const coordinates = item.attributes.coordinates ?? [];

  const packages: Array<{
    name: string | null;
    version: string | null;
    purl: string | null;
  }> = [];

  for (const coord of coordinates) {
    const reps = coord.representations ?? [];
    for (const rep of reps) {
      if (!('dependency' in rep)) continue;

      packages.push({
        name: rep.dependency.package_name,
        version: normalizeVersion(rep.dependency.package_version),
        purl: null,
      });
    }
  }

  const fixVersions: string[] = [];
  for (const coord of coordinates) {
    const remedies = coord.remedies ?? [];
    for (const remedy of remedies) {
      fixVersions.push(...parseUpgradePackageValue(remedy.meta?.data.fixed_in));
    }
  }

  const firstPackage = packages[0] ?? null;
  return {
    name: firstPackage?.name ?? null,
    version: firstPackage?.version ?? null,
    purl: firstPackage?.purl ?? null,
    fixVersions: [...new Set(fixVersions)],
  };
}

// ---------------------------------------------------------------------------
// Code data extraction
// ---------------------------------------------------------------------------

export function extractCodeDataFromIssue(item: RestIssue): LedgerIssue['code'] {
  const coordinates = item.attributes.coordinates ?? [];

  for (const coord of coordinates) {
    const reps = coord.representations ?? [];
    for (const rep of reps) {
      if ('sourceLocation' in rep) {
        const loc = rep.sourceLocation;
        return {
          file: loc.file,
          startLine: loc.region?.start.line ?? null,
          endLine: loc.region?.end.line ?? null,
          commitId: loc.commit_id ?? null,
        };
      }
    }
  }

  return null;
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
