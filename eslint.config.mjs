import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import onlyWarn from 'eslint-plugin-only-warn';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import unusedImports from 'eslint-plugin-unused-imports';
import tseslint from 'typescript-eslint';

import { prettierrc } from './prettierrc.js';

export default defineConfig([
  js.configs.recommended,
  eslintPluginPrettierRecommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      'prettier/prettier': ['error', prettierrc],
    },
  },
  {
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['../**/packages/**'],
              message:
                'Relative imports across monorepo boundaries are not allowed (e.g. ../../packages/...). Use workspace package imports instead (e.g. @pkg/*).',
            },
            {
              group: ['../**/apps/**'],
              message:
                'Relative imports across monorepo boundaries are not allowed (e.g. ../../apps/...). Use a proper public API/workspace import instead.',
            },
          ],
        },
      ],
    },
  },
  {
    plugins: {
      'unused-imports': unusedImports,
    },
    rules: {
      'no-unused-vars': 'off',
      'unused-imports/no-unused-imports': 'error',
    },
  },
  {
    plugins: {
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',
    },
  },
  {
    plugins: {
      onlyWarn,
    },
  },
  {
    ignores: [
      '**/*.js',
      '**/*.d.ts',
      'dist/**',
      'node_modules/**',
    ],
  },
]);
