import createClient from 'openapi-fetch';

import { env } from '../config.js';
import type { components, paths } from './types/snyk-rest.d.ts';

const JSON_API_CONTENT_TYPE = 'application/vnd.api+json';

async function snykFetch(input: RequestInfo | URL, init?: RequestInit) {
  const url =
    typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

  try {
    return await fetch(input, init);
  } catch (cause) {
    throw new Error(`Snyk API network error\nURL: ${url}`, { cause });
  }
}

export const snykRestClient = createClient<paths>({
  baseUrl: `${env.SNYK_API_BASE}/rest`,
  fetch: snykFetch,
  headers: {
    Authorization: `token ${env.SNYK_TOKEN}`,
    Accept: JSON_API_CONTENT_TYPE,
    'Content-Type': JSON_API_CONTENT_TYPE,
  },
});

function formatSnykError(error: unknown) {
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;

  try {
    return JSON.stringify(error, null, 2);
  } catch {
    return String(error);
  }
}

export function expectSnykRestData<T>(result: {
  data?: T;
  error?: unknown;
  response: Response;
}) {
  if (result.error) {
    throw new Error(
      `Snyk API error ${result.response.status} ${result.response.statusText}\nURL: ${result.response.url}\nResponse: ${formatSnykError(result.error)}`,
    );
  }

  if (typeof result.data === 'undefined') {
    throw new Error(`Snyk API returned no data\nURL: ${result.response.url}`);
  }

  return result.data;
}

export async function snykGetRaw(path: string, accept = 'application/json') {
  const url = `${env.SNYK_API_BASE}${path}`;

  const response = await snykFetch(url, {
    method: 'GET',
    headers: {
      Authorization: `token ${env.SNYK_TOKEN}`,
      Accept: accept,
      'Content-Type': accept,
    },
  });

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

export type SnykIssueTypeFilter = components['schemas']['IssueTypeFilter'];
export type SnykScanItemType = components['parameters']['ScanItemType'];
export type SnykStatusFilter = components['parameters']['Status'][number];
export type SnykSeverityFilter =
  components['parameters']['EffectiveSeverityLevel'][number];
