import { readFileSync } from 'node:fs';

const PACKAGE_JSON_URL = new URL('../package.json', import.meta.url);
const DEVELOPMENT_VERSION = '0.0.0-development';

function normalizeVersion(version: string): string {
  return version.trim().replace(/^v/, '');
}

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON_URL, 'utf8')) as {
      version?: unknown;
    };

    return typeof pkg.version === 'string'
      ? normalizeVersion(pkg.version)
      : DEVELOPMENT_VERSION;
  } catch {
    return DEVELOPMENT_VERSION;
  }
}

export const serverVersion = readPackageVersion();
