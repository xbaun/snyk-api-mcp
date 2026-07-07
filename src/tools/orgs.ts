import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { env } from '../config.js';
import { expectSnykRestData, snykRestClient } from '../snyk/client.js';
import type { SnykItem } from '../utils/helpers.js';

export function registerOrgTools(server: McpServer) {
  // -----------------------------------------------------------------------
  // snyk_resolve_org_id
  // -----------------------------------------------------------------------

  server.registerTool(
    'snyk_resolve_org_id',
    {
      description:
        "Resolve a Snyk organization slug (e.g. 'my-snyk-org') to its UUID. " +
        'Requires an exact slug match.',
      inputSchema: {
        orgSlug: z
          .string()
          .describe("Exact organization slug, e.g. 'my-snyk-org'"),
      },
    },
    async ({ orgSlug }) => {
      const data = expectSnykRestData(
        await snykRestClient.GET('/orgs', {
          params: {
            query: {
              version: env.SNYK_API_VERSION,
              limit: 100,
            },
          },
        }),
      );
      const orgs = Array.isArray(data?.data) ? data.data : [];
      const exactSlug = orgSlug.trim().toLowerCase();
      const match = orgs.find(
        (org: SnykItem) =>
          ((org?.attributes?.slug as string) ?? '').toLowerCase() === exactSlug,
      );

      if (!match?.id) {
        throw new Error(
          `No Snyk organization found for exact slug '${orgSlug}'.`,
        );
      }

      const attributes = (match.attributes ?? {}) as Record<string, unknown>;

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                query: { orgSlug },
                orgId: match.id,
                org: {
                  id: match.id,
                  slug: attributes.slug,
                  name: attributes.name,
                  groupName: (
                    attributes.group as Record<string, unknown> | undefined
                  )?.name,
                },
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

      const data = expectSnykRestData(
        await snykRestClient.GET('/orgs/{org_id}/projects', {
          params: {
            path: { org_id: orgId },
            query: {
              version: apiVersion,
              limit: 100,
              target_id: targetId ? [targetId] : undefined,
            },
          },
        }),
      );

      const projects = (Array.isArray(data?.data) ? data.data : []).map(
        (p: SnykItem) => ({
          id: p.id,
          name: p?.attributes?.name,
          type: p?.attributes?.type,
          origin: p?.attributes?.origin,
          status: p?.attributes?.status,
          created: p?.attributes?.created,
          targetId: Array.isArray(p?.relationships?.target?.data)
            ? p.relationships?.target?.data[0]?.id
            : p?.relationships?.target?.data?.id,
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

      const data = expectSnykRestData(
        await snykRestClient.GET('/orgs/{org_id}/targets', {
          params: {
            path: { org_id: orgId },
            query: {
              version: apiVersion,
              limit: 100,
              display_name: displayName,
            },
          },
        }),
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
