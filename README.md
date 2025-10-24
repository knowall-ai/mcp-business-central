# @knowall-ai/mcp-business-central

Model Context Protocol (MCP) server for Microsoft Dynamics 365 Business Central. Provides AI assistants with direct access to Business Central data through properly formatted API v2.0 calls.

## Features

- ✅ **Correct API URLs**: Uses proper `/companies(id)/resource` format (no ODataV4 segment)
- ✅ **Zero Installation**: Run with `npx` - no pre-installation required
- ✅ **Azure CLI Auth**: Leverages existing Azure CLI authentication
- ✅ **Clean Tool Names**: No prefixes, just `get_schema`, `list_items`, etc.
- ✅ **Full CRUD**: Create, read, update, and delete Business Central records

## Installation

### Using npx (Recommended)

No installation needed! Configure in Claude Desktop or Claude Code:

```json
{
  "mcpServers": {
    "business-central": {
      "type": "stdio",
      "command": "cmd",
      "args": ["/c", "npx", "-y", "@knowall-ai/mcp-business-central"],
      "env": {
        "BC_URL_SERVER": "https://api.businesscentral.dynamics.com/v2.0/{tenant-id}/{environment}/api/v2.0",
        "BC_COMPANY": "Your Company Name",
        "BC_AUTH_TYPE": "azure_cli"
      }
    }
  }
}
```

**Note for Windows**: Use `cmd` with `/c` as shown above for proper npx execution.

### Local Development

```bash
git clone https://github.com/knowall-ai/mcp-business-central.git
cd mcp-business-central
npm install
npm run build
node build/index.js
```

## Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `BC_URL_SERVER` | Yes | Business Central API base URL | `https://api.businesscentral.dynamics.com/v2.0/{tenant}/Production/api/v2.0` |
| `BC_COMPANY` | Yes | Company display name | `KnowAll Ltd` |
| `BC_AUTH_TYPE` | No | Authentication type (default: `azure_cli`) | `azure_cli` |

### Getting Your Configuration Values

1. **Tenant ID**: Find in Azure Portal → Azure Active Directory → Overview
2. **Environment**: Usually `Production` or `Sandbox`
3. **Company Name**: The display name shown in Business Central

Example URL format:
```
https://api.businesscentral.dynamics.com/v2.0/00000000-0000-0000-0000-000000000000/Production/api/v2.0
```

## Prerequisites

- **Azure CLI**: Must be installed and authenticated
  - Install: https://docs.microsoft.com/cli/azure/install-azure-cli
  - Login: `az login`
  - Get token: `az account get-access-token --resource https://api.businesscentral.dynamics.com`

## Available Tools

### 1. `get_schema`
Get OData metadata for a Business Central resource.

**Parameters:**
- `resource` (string, required): Resource name (e.g., `customers`, `contacts`, `salesOpportunities`)

**Example:**
```json
{
  "resource": "customers"
}
```

### 2. `list_items`
List items with optional filtering and pagination.

**Parameters:**
- `resource` (string, required): Resource name
- `filter` (string, optional): OData filter expression
- `top` (number, optional): Maximum number of items to return
- `skip` (number, optional): Number of items to skip for pagination

**Example:**
```json
{
  "resource": "customers",
  "filter": "displayName eq 'Contoso'",
  "top": 10
}
```

### 3. `get_items_by_field`
Get items matching a specific field value.

**Parameters:**
- `resource` (string, required): Resource name
- `field` (string, required): Field name to filter by
- `value` (string, required): Value to match

**Example:**
```json
{
  "resource": "contacts",
  "field": "companyName",
  "value": "Contoso Ltd"
}
```

### 4. `create_item`
Create a new item in Business Central.

**Parameters:**
- `resource` (string, required): Resource name
- `item_data` (object, required): Item data to create

**Example:**
```json
{
  "resource": "contacts",
  "item_data": {
    "displayName": "John Doe",
    "companyName": "Contoso Ltd",
    "email": "john.doe@contoso.com"
  }
}
```

### 5. `update_item`
Update an existing item.

**Parameters:**
- `resource` (string, required): Resource name
- `item_id` (string, required): Item ID (GUID)
- `item_data` (object, required): Fields to update

**Example:**
```json
{
  "resource": "customers",
  "item_id": "1366066e-7688-f011-b9d1-6045bde9b95f",
  "item_data": {
    "displayName": "Updated Name"
  }
}
```

### 6. `delete_item`
Delete an item from Business Central.

**Parameters:**
- `resource` (string, required): Resource name
- `item_id` (string, required): Item ID (GUID)

**Example:**
```json
{
  "resource": "contacts",
  "item_id": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
}
```

## Common Resources

- `companies` - Company information
- `customers` - Customer records
- `contacts` - Contact records
- `salesOpportunities` - Sales opportunities
- `salesQuotes` - Sales quotes
- `salesOrders` - Sales orders
- `salesInvoices` - Sales invoices
- `items` - Product/service items
- `vendors` - Vendor records

## Differences from Python Version

This TypeScript implementation fixes critical bugs in the original Python `mcp-business-central-server`:

1. **Correct URL Format**:
   - ❌ Python: `/ODataV4/Company('name')/resource`
   - ✅ TypeScript: `/companies(id)/resource`

2. **Company Lookup**:
   - ❌ Python: Uses company name directly (fails)
   - ✅ TypeScript: Queries company ID by name, caches result

3. **Tool Names**:
   - ❌ Python: `BC_List_Items`, `BC_Create_Item`, etc.
   - ✅ TypeScript: `list_items`, `create_item`, etc.

4. **Installation**:
   - ❌ Python: Requires `pip install`, Python environment
   - ✅ TypeScript: Zero-install with `npx`

## Troubleshooting

### 401 Unauthorized
- Ensure Azure CLI is logged in: `az login`
- Verify you have access to Business Central in your tenant
- Test token retrieval: `az account get-access-token --resource https://api.businesscentral.dynamics.com`

### Company Not Found
- Check company name matches exactly (case-sensitive)
- Verify company exists: Access Business Central web UI
- Ensure URL includes correct tenant ID and environment

### Resource Not Found
- Check resource name spelling (e.g., `customers` not `customer`)
- Some resources may not be available in your Business Central version
- Use `get_schema` to explore available resources

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Watch mode for development
npm run dev
```

## License

MIT

## Contributing

Issues and pull requests welcome at https://github.com/knowall-ai/mcp-business-central

## Related Projects

- Original Python implementation: [mcp-business-central-server](https://github.com/Sofias-ai/mcp-business-central-server)
- MCP Specification: [modelcontextprotocol.io](https://modelcontextprotocol.io)
