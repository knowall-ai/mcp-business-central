[![smithery badge](https://smithery.ai/badge/@knowall-ai/mcp-business-central)](https://smithery.ai/server/@knowall-ai/mcp-business-central)

# Microsoft Business Central MCP Server

<img width="1536" height="1024" alt="mcp-business-central" src="https://github.com/user-attachments/assets/13932bfd-a5b9-4668-a7cd-ac9549a09673" />

Model Context Protocol (MCP) server for Microsoft Dynamics 365 Business Central. Provides AI assistants with direct access to Business Central data through properly formatted API v2.0 calls.

## Features

- ✅ **Correct API URLs**: Uses proper `/companies(id)/resource` format (no ODataV4 segment)
- ✅ **Zero Installation**: Run with `npx` - no pre-installation required
- ✅ **Flexible Authentication**: Azure CLI for local dev, Managed Identity for cloud deployments
- ✅ **Dual Transport**: STDIO for local use, HTTP for cloud deployments
- ✅ **Cloud Ready**: Docker support for Azure Container Apps and Smithery
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
        "BC_COMPANY": "Your Company Name"
      }
    }
  }
}
```

**Note for Windows**: Use `cmd` with `/c` as shown above for proper npx execution.

### Using Smithery

Install via [Smithery](https://smithery.ai):

```bash
npx -y @smithery/cli install @knowall-ai/mcp-business-central --client claude
```

### Azure Container Apps Deployment

Deploy as an HTTP server for Azure AI Foundry or other cloud services:

1. **Build and push Docker image:**

```bash
docker build -t your-registry.azurecr.io/bc-mcp:latest .
docker push your-registry.azurecr.io/bc-mcp:latest
```

2. **Create Container App:**

```bash
az containerapp create \
  --name bc-mcp-server \
  --resource-group your-rg \
  --environment your-env \
  --image your-registry.azurecr.io/bc-mcp:latest \
  --target-port 3000 \
  --ingress external \
  --env-vars \
    BC_URL_SERVER="https://api.businesscentral.dynamics.com/v2.0/{tenant}/{environment}/api/v2.0" \
    BC_COMPANY="Your Company Name" \
  --registry-server your-registry.azurecr.io \
  --system-assigned
```

3. **Assign Managed Identity permissions:**

Grant the container app's managed identity access to Business Central APIs in Azure AD.

4. **Use the MCP endpoint:**

The server exposes:
- `/mcp` - MCP protocol endpoint (POST)
- `/health` - Health check endpoint (GET)

### Local Development

**STDIO mode (for Claude Desktop/Code):**
```bash
git clone https://github.com/knowall-ai/mcp-business-central.git
cd mcp-business-central
npm install
npm run build
node build/index.js
```

**HTTP mode (for testing cloud deployment):**
```bash
npm run build
npm run start:http
# Server runs at http://localhost:3000/mcp
```

## Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `BC_URL_SERVER` | Yes | Business Central API base URL | `https://api.businesscentral.dynamics.com/v2.0/{tenant}/Production/api/v2.0` |
| `BC_COMPANY` | Yes | Company display name | `KnowAll Ltd` |
| `PORT` | No | HTTP server port (default: 3000) | `3000` |

### Getting Your Configuration Values

1. **Tenant ID**: Find in Azure Portal → Azure Active Directory → Overview
2. **Environment**: Usually `Production` or `Sandbox`
3. **Company Name**: The display name shown in Business Central

Example URL format:
```
https://api.businesscentral.dynamics.com/v2.0/00000000-0000-0000-0000-000000000000/Production/api/v2.0
```

## Authentication

The server uses **DefaultAzureCredential** which automatically tries multiple authentication methods:

### Local Development (STDIO mode)
- **Azure CLI**: Recommended for local development
  - Install: https://docs.microsoft.com/cli/azure/install-azure-cli
  - Login: `az login`
  - Test: `az account get-access-token --resource https://api.businesscentral.dynamics.com`

### Cloud Deployment (HTTP mode)
- **Managed Identity**: Automatically used when deployed to Azure Container Apps
  - No credentials needed in code
  - Assign the container app's managed identity permissions to Business Central APIs

### Alternative Methods
DefaultAzureCredential also supports:
- Environment variables (service principal credentials)
- Visual Studio authentication
- VS Code authentication

The credential tries each method in order until one succeeds.

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

- MCP Specification: [modelcontextprotocol.io](https://modelcontextprotocol.io)
