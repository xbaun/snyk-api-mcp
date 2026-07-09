import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import process from 'node:process';

const repoRoot = resolve(import.meta.dirname, '..');
const layoutDir = resolve(repoRoot, 'layout');
const outputFile = resolve(repoRoot, 'build', 'snyk-api-mcp-layout.tar.gz');

try {
  statSync(layoutDir);
} catch {
  throw new Error(`Layout directory not found: ${layoutDir}`);
}

mkdirSync(dirname(outputFile), { recursive: true });
rmSync(outputFile, { force: true });

const tarArgs = [
  '--exclude=__pycache__',
  '--exclude=*.py[cod]',
  '--exclude=.DS_Store',
  '--exclude=Thumbs.db',
  '-czf',
  outputFile,
  '-C',
  layoutDir,
  '.',
];

execFileSync('tar', tarArgs, { stdio: 'inherit' });

process.stdout.write(`Created layout archive: ${outputFile}\n`);
