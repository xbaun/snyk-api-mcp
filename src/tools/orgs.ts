import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { resolveRestApiVersion, snykRestApi } from '../snyk/client.js';
import type { operations } from '../snyk/types/snyk-rest.d.ts';
import {
  extractNextCursor,
  requireUuid,
  type SnykItem,
} from '../utils/helpers.js';

type ListProjectsQuery = operations['listOrgProjects']['parameters']['query'];

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
      const apiVersion = resolveRestApiVersion();

      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs', {
          params: {
            query: {
              version: apiVersion,
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
        'List all Snyk projects for an organization, optionally filtered by target_id, type, or paginated with a cursor. ' +
        'Each project includes a latest issue count breakdown (critical, high, medium, low). ' +
        'Use this after snyk_get_targets to get full project details for a specific target/repository.',
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
        types: z
          .array(z.string().trim().min(1))
          .optional()
          .describe(
            "Filter by project type, e.g. ['sast'] for Snyk Code projects only. " +
              'Use when you want to narrow results to a specific kind of project.',
          ),
        startingAfter: z
          .string()
          .optional()
          .describe(
            'Pagination cursor. Pass the `nextCursor` value returned by a previous call to get the next page.',
          ),
      },
    },
    async ({ orgId, targetId, types, startingAfter }) => {
      requireUuid('orgId', orgId);
      if (targetId) requireUuid('targetId', targetId);

      const apiVersion = resolveRestApiVersion();

      const query: ListProjectsQuery = {
        version: apiVersion,
        limit: 100,
        'meta.latest_issue_counts': true,
      };

      if (targetId) query.target_id = [targetId];
      if (types && types.length > 0) query.types = types;
      if (startingAfter) query.starting_after = startingAfter;

      const rawResult = await snykRestApi.client.GET(
        '/orgs/{org_id}/projects',
        {
          params: {
            path: { org_id: orgId },
            query,
          },
        },
      );

      const page = snykRestApi.expectData(rawResult);

      const nextCursor = extractNextCursor(
        (page as { links?: Record<string, unknown> }).links,
      );

      const projects = (Array.isArray(page.data) ? page.data : []).map(
        (p: SnykItem) => {
          const rawMeta = (p?.meta ?? {}) as Record<string, unknown>;
          const counts = (rawMeta.latest_issue_counts ?? {}) as Record<
            string,
            unknown
          >;

          return {
            id: p.id,
            name: p?.attributes?.name,
            type: p?.attributes?.type,
            origin: p?.attributes?.origin,
            status: p?.attributes?.status,
            created: p?.attributes?.created,
            targetId: Array.isArray(p?.relationships?.target?.data)
              ? p.relationships?.target?.data[0]?.id
              : p?.relationships?.target?.data?.id,
            issueCounts: {
              critical: (counts.critical as number) ?? 0,
              high: (counts.high as number) ?? 0,
              medium: (counts.medium as number) ?? 0,
              low: (counts.low as number) ?? 0,
              updatedAt: (counts.updated_at as string) ?? null,
            },
          };
        },
      );

      const result: Record<string, unknown> = {
        query: { orgId, targetId, types, startingAfter },
        matchCount: projects.length,
        projects,
      };

      if (nextCursor) {
        result.nextCursor = nextCursor;
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
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
      },
    },
    async ({ orgId, displayName }) => {
      requireUuid('orgId', orgId);

      const apiVersion = resolveRestApiVersion();

      const data = snykRestApi.expectData(
        await snykRestApi.client.GET('/orgs/{org_id}/targets', {
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
                query: { orgId, displayName },
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
