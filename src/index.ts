#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { registerAnalysisTools } from './tools/analysis.js';
import { registerIssueTools } from './tools/issues.js';
import { registerLedgerSeedTool } from './tools/ledger-seed.js';
import { registerOnboardingTool } from './tools/onboarding.js';
import { registerOrgTools } from './tools/orgs.js';
import { serverVersion } from './version.js';

const server = new McpServer({
  name: 'snyk-api-mcp',
  version: serverVersion,
});

registerOnboardingTool(server);
registerOrgTools(server);
registerIssueTools(server);
registerAnalysisTools(server);
registerLedgerSeedTool(server);

const transport = new StdioServerTransport();
await server.connect(transport);
