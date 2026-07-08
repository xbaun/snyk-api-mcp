import createClient from 'openapi-fetch';

import { env } from '../config.js';
import type { paths as v1Paths } from './types/snyk-api-v1-types.d.ts';
import type { components, paths } from './types/snyk-rest.d.ts';

const JSON_API_CONTENT_TYPE = 'application/vnd.api+json';

type SnykApiName = 'REST' | 'V1';

type OpenApiFetchResult<T> = {
  data?: T;
  error?: unknown;
  response: Response;
};

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

function expectSnykApiData<T>(
  apiName: SnykApiName,
  result: OpenApiFetchResult<T>,
) {
  if (result.error) {
    throw new Error(
      `Snyk ${apiName} API error ${result.response.status} ${result.response.statusText}\nURL: ${result.response.url}\nResponse: ${formatSnykError(result.error)}`,
    );
  }

  if (typeof result.data === 'undefined') {
    throw new Error(
      `Snyk ${apiName} API returned no data\nURL: ${result.response.url}`,
    );
  }

  return result.data;
}

function createSnykApiClient<TPaths extends object>({
  apiName,
  basePath,
  accept,
  contentType,
}: {
  apiName: SnykApiName;
  basePath: '/rest' | '/v1';
  accept: string;
  contentType: string;
}) {
  const client = createClient<TPaths>({
    baseUrl: `${env.SNYK_API_BASE}${basePath}`,
    fetch: snykFetch,
    headers: {
      Authorization: `token ${env.SNYK_TOKEN}`,
      Accept: accept,
      'Content-Type': contentType,
    },
  });

  return {
    apiName,
    baseUrl: `${env.SNYK_API_BASE}${basePath}`,
    client,
    expectData<T>(result: OpenApiFetchResult<T>) {
      return expectSnykApiData(apiName, result);
    },
  };
}

export const snykRestApi = createSnykApiClient<paths>({
  apiName: 'REST',
  basePath: '/rest',
  accept: JSON_API_CONTENT_TYPE,
  contentType: JSON_API_CONTENT_TYPE,
});

export const snykV1Api = createSnykApiClient<v1Paths>({
  apiName: 'V1',
  basePath: '/v1',
  accept: 'application/json',
  contentType: 'application/json',
});

export const snykRestClient = snykRestApi.client;
export const snykV1Client = snykV1Api.client;

function formatSnykError(error: unknown) {
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;

  try {
    return JSON.stringify(error, null, 2);
  } catch {
    return String(error);
  }
}

export function resolveRestApiVersion() {
  return env.SNYK_API_VERSION;
}

export function expectSnykRestData<T>(result: OpenApiFetchResult<T>) {
  return snykRestApi.expectData(result);
}

export function expectSnykV1Data<T>(result: OpenApiFetchResult<T>) {
  return snykV1Api.expectData(result);
}

export type SnykIssueTypeFilter = components['schemas']['IssueTypeFilter'];
export type SnykScanItemType = components['parameters']['ScanItemType'];
export type SnykStatusFilter = components['parameters']['Status'][number];
export type SnykSeverityFilter =
  components['parameters']['EffectiveSeverityLevel'][number];
