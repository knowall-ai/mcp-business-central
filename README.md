[![smithery badge](https://smithery.ai/badge/@knowall-ai/mcp-business-central)](https://smithery.ai/server/@knowall-ai/mcp-business-central)

# Microsoft Business Central MCP Server

<img width="1536" height="1024" alt="mcp-business-central" src="https://github.com/user-attachments/assets/13932bfd-a5b9-4668-a7cd-ac9549a09673" />

Model Context Protocol (MCP) server for Microsoft Dynamics 365 Business Central. Provides AI assistants with direct access to Business Central data through properly formatted API v2.0 calls.

## Features

- ✅ **Correct API URLs**: Uses proper `/companies(id)/resource` format (no ODataV4 segment)
- ✅ **Zero Installation**: Run with `npx` - no pre-installation required
- ✅ **Azure CLI Auth**: Leverages existing Azure CLI authentication
- ✅ **Client Credentials Auth**: Service-to-service authentication for AI agents
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

### Using Smithery

Install via [Smithery](https://smithery.ai):

```bash
npx -y @smithery/cli install @knowall-ai/mcp-business-central --client claude
```

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
| `BC_AUTH_TYPE` | No | Authentication type (default: `azure_cli`) | `azure_cli` or `client_credentials` |
| `BC_TENANT_ID` | For client_credentials | Azure AD tenant ID | `00000000-0000-0000-0000-000000000000` |
| `BC_CLIENT_ID` | For client_credentials | App registration client ID | `00000000-0000-0000-0000-000000000000` |
| `BC_CLIENT_SECRET` | For client_credentials | App registration client secret | `your-secret-value` |

### Getting Your Configuration Values

1. **Tenant ID**: Find in Azure Portal → Azure Active Directory → Overview
2. **Environment**: Usually `Production` or `Sandbox`
3. **Company Name**: The display name shown in Business Central

Example URL format:
```
https://api.businesscentral.dynamics.com/v2.0/00000000-0000-0000-0000-000000000000/Production/api/v2.0
```

## Authentication

> **Recommendation**: Use `azure_cli` authentication - it's simpler to set up and more reliable. The `client_credentials` method is also supported but has known configuration challenges with Business Central's Microsoft Entra Applications setup. See [docs/TROUBLESHOOTING.adoc](docs/TROUBLESHOOTING.adoc) for details.

### Option 1: Azure CLI (Recommended)

The simplest and most reliable authentication method. Uses your existing Azure CLI login.

**Prerequisites:**
- Install Azure CLI: https://docs.microsoft.com/cli/azure/install-azure-cli
- Login: `az login`
- Verify access: `az account get-access-token --resource https://api.businesscentral.dynamics.com`

**Configuration:**
```json
{
  "mcpServers": {
    "business-central": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@knowall-ai/mcp-business-central"],
      "env": {
        "BC_AUTH_TYPE": "azure_cli",
        "BC_URL_SERVER": "https://api.businesscentral.dynamics.com/v2.0/{tenant-id}/Production/api/v2.0",
        "BC_COMPANY": "My Company"
      }
    }
  }
}
```

### Option 2: Client Credentials (Service-to-Service)

For automated systems that need to run without user interaction. This method uses OAuth 2.0 client credentials flow.

> **Note**: This method has known configuration challenges. The Business Central "Microsoft Entra Applications" setup can be complex and the application user creation may not work as expected. See [docs/TROUBLESHOOTING.adoc](docs/TROUBLESHOOTING.adoc) for detailed guidance.

**Setup Overview:**

1. **Create Azure App Registration**:
   - Go to Azure Portal → Azure Active Directory → App registrations
   - Create new registration (single tenant)
   - Add API permission: Dynamics 365 Business Central → `app_access` (Application permission, NOT Delegated)
   - Grant admin consent for the permission
   - Add redirect URI: `https://businesscentral.dynamics.com/OAuthLanding.htm`

2. **Generate Client Secret**:
   - In your app registration, go to Certificates & secrets
   - Create a new client secret and save it securely

3. **Configure Business Central**:
   - In Business Central, search for "Microsoft Entra Applications"
   - Click **+ New** and enter your app's Client ID
   - Set a Description (this becomes the application user name)
   - Set State to "Enabled" - you should see "A user named '[Description]' will be created"
   - Add permission sets: `D365 BUS FULL ACCESS` (recommended) or `D365 READ`
   - Leave Company field blank for all companies access
   - Click "Grant Consent"

4. **Verify Setup**:
   - The application user should appear in the Users list in Business Central
   - If not, see [docs/TROUBLESHOOTING.adoc](docs/TROUBLESHOOTING.adoc) for solutions

**References**:
- [Microsoft: Service-to-service authentication](https://learn.microsoft.com/en-us/dynamics365/business-central/dev-itpro/administration/automation-apis-using-s2s-authentication)
- [Business Central API Authentication](https://learn.microsoft.com/en-us/dynamics365/business-central/dev-itpro/webservices/authenticate-web-services-using-oauth)

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

See [docs/TROUBLESHOOTING.adoc](docs/TROUBLESHOOTING.adoc) for detailed troubleshooting guides covering:

- Authentication issues (401 errors, token problems)
- `client_credentials` setup challenges and known issues
- Company not found errors
- Environment-specific configuration (Production vs Sandbox)

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
