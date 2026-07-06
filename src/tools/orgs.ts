import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { env } from '../config.js';
import { snykGet } from '../snyk/client.js';
import type { SnykItem } from '../utils/helpers.js';

export function registerOrgTools(server: McpServer) {
  // -----------------------------------------------------------------------
  // snyk_resolve_org_id
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_resolve_org_id',
    {
      description:
        "Resolve a Snyk organization slug (e.g. 'my-snyk-org') or partial name to its UUID. " +
        'Use this before calling tools that require an orgId when you only have a human-readable org name.',
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
        `/rest/orgs?version=${encodeURIComponent(env.SNYK_API_VERSION)}&limit=100`,
      );
      const orgs = Array.isArray(data?.data) ? data.data : [];
      const lower = orgSlug.toLowerCase();

      const matches = orgs
        .filter((org: SnykItem) => {
          const slug = (org?.attributes?.slug as string) ?? '';
          const name = (org?.attributes?.name as string) ?? '';
          return (
            slug.toLowerCase().includes(lower) ||
            name.toLowerCase().includes(lower)
          );
        })
        .map((org: SnykItem) => ({
          id: org.id,
          slug: org?.attributes?.slug,
          name: org?.attributes?.name,
          groupName: (
            org?.attributes?.group as Record<string, unknown> | undefined
          )?.name,
        }));

      return {
        content: [
          {
            type: 'text',
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

  // -----------------------------------------------------------------------
  // snyk_get_projects
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_projects',
    {
      description:
        'List all Snyk projects for an organization, optionally filtered by target_id. ' +
        'Use this after snyk_get_targets to get full project details (id, name, type, origin, status) ' +
        'for a specific target/repository.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        targetId: z
          .string()
          .optional()
          .describe(
            'Filter projects by target ID (UUID). Use snyk_get_targets first to find the target ID for a repository.',
          ),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({ orgId, targetId, version }) => {
      const apiVersion = version || env.SNYK_API_VERSION;

      const params = new URLSearchParams({
        version: apiVersion,
        limit: '100',
      });
      if (targetId) params.set('target_id', targetId);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/projects?${params.toString()}`,
      );

      const projects = (Array.isArray(data?.data) ? data.data : []).map(
        (p: SnykItem) => ({
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
            type: 'text',
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

  // -----------------------------------------------------------------------
  // snyk_get_targets
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_get_targets',
    {
      description:
        'List Snyk targets (repositories/containers) for an organization, ' +
        'optionally filtered by display name. ' +
        'Use snyk_get_projects to list all projects for a specific target.',
      inputSchema: {
        orgId: z
          .string()
          .describe(
            'Snyk organization UUID. Use snyk_resolve_org_id first if you only have a slug.',
          ),
        displayName: z
          .string()
          .optional()
          .describe(
            'Filter targets by display name (URL-encoded). ' +
              "E.g. 'my-github-org/my-repo' for the target with that display name.",
          ),
        version: z
          .string()
          .optional()
          .describe('Snyk REST API version, e.g. 2026-03-25'),
      },
    },
    async ({ orgId, displayName, version }) => {
      const apiVersion = version || env.SNYK_API_VERSION;

      const params = new URLSearchParams({
        version: apiVersion,
        limit: '100',
      });
      if (displayName) params.set('display_name', displayName);

      const data = await snykGet(
        `/rest/orgs/${encodeURIComponent(orgId)}/targets?${params.toString()}`,
      );

      const targets = (Array.isArray(data?.data) ? data.data : []).map(
        (t: SnykItem) => ({
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
            type: 'text',
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
}
