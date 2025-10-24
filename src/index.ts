#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { BusinessCentralClient } from './business-central-client.js';

// Read configuration from environment variables
const BC_URL_SERVER = process.env.BC_URL_SERVER;
const BC_COMPANY = process.env.BC_COMPANY;
const BC_AUTH_TYPE = process.env.BC_AUTH_TYPE || 'azure_cli';

if (!BC_URL_SERVER || !BC_COMPANY) {
  console.error('Error: BC_URL_SERVER and BC_COMPANY environment variables are required');
  process.exit(1);
}

if (BC_AUTH_TYPE !== 'azure_cli') {
  console.error('Error: Only azure_cli authentication is currently supported');
  process.exit(1);
}

// Create Business Central client
const bcClient = new BusinessCentralClient({
  serverUrl: BC_URL_SERVER,
  companyName: BC_COMPANY,
  authType: BC_AUTH_TYPE
});

// Create MCP server
const server = new Server(
  {
    name: 'business-central',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'get_schema',
        description: 'Get schema information for a Business Central resource',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts, salesOpportunities)',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'list_items',
        description: 'Get items from Business Central with filtering and pagination',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts, salesOpportunities)',
            },
            filter: {
              type: 'string',
              description: 'OData filter expression (optional)',
            },
            top: {
              type: 'number',
              description: 'Maximum number of items to return (optional)',
            },
            skip: {
              type: 'number',
              description: 'Number of items to skip for pagination (optional)',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'get_items_by_field',
        description: 'Get items matching a field value',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts)',
            },
            field: {
              type: 'string',
              description: 'The field name to filter by',
            },
            value: {
              type: 'string',
              description: 'The value to match',
            },
          },
          required: ['resource', 'field', 'value'],
        },
      },
      {
        name: 'create_item',
        description: 'Create a new item in Business Central',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts)',
            },
            item_data: {
              type: 'object',
              description: 'The item data to create',
            },
          },
          required: ['resource', 'item_data'],
        },
      },
      {
        name: 'update_item',
        description: 'Update an existing item in Business Central',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts)',
            },
            item_id: {
              type: 'string',
              description: 'The ID of the item to update',
            },
            item_data: {
              type: 'object',
              description: 'The item data to update',
            },
          },
          required: ['resource', 'item_id', 'item_data'],
        },
      },
      {
        name: 'delete_item',
        description: 'Delete an item from Business Central',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'The resource name (e.g., customers, contacts)',
            },
            item_id: {
              type: 'string',
              description: 'The ID of the item to delete',
            },
          },
          required: ['resource', 'item_id'],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case 'get_schema': {
        const { resource } = args as { resource: string };
        const result = await bcClient.getSchema(resource);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'list_items': {
        const { resource, filter, top, skip } = args as {
          resource: string;
          filter?: string;
          top?: number;
          skip?: number;
        };
        const result = await bcClient.listItems(resource, { filter, top, skip });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'get_items_by_field': {
        const { resource, field, value } = args as {
          resource: string;
          field: string;
          value: string;
        };
        const result = await bcClient.getItemsByField(resource, field, value);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'create_item': {
        const { resource, item_data } = args as {
          resource: string;
          item_data: any;
        };
        const result = await bcClient.createItem(resource, item_data);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_item': {
        const { resource, item_id, item_data } = args as {
          resource: string;
          item_id: string;
          item_data: any;
        };
        const result = await bcClient.updateItem(resource, item_id, item_data);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_item': {
        const { resource, item_id } = args as {
          resource: string;
          item_id: string;
        };
        await bcClient.deleteItem(resource, item_id);
        return {
          content: [
            {
              type: 'text',
              text: 'Item deleted successfully',
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Business Central MCP server running on stdio');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
