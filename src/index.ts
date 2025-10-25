#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { BusinessCentralClient } from './business-central-client.js';
import { createMCPServer } from './server.js';

// Read configuration from environment variables
const BC_URL_SERVER = process.env.BC_URL_SERVER;
const BC_COMPANY = process.env.BC_COMPANY;

if (!BC_URL_SERVER || !BC_COMPANY) {
  console.error('Error: BC_URL_SERVER and BC_COMPANY environment variables are required');
  process.exit(1);
}

// Create Business Central client
const bcClient = new BusinessCentralClient({
  serverUrl: BC_URL_SERVER,
  companyName: BC_COMPANY,
});

// Create MCP server with shared logic
const server = createMCPServer(bcClient);

// Start server with STDIO transport
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Business Central MCP server running on stdio');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
