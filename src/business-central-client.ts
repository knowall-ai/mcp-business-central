import { AzureCliCredential, ClientSecretCredential, TokenCredential } from '@azure/identity';

export interface BusinessCentralConfig {
  serverUrl: string;
  companyName: string;
  authType: 'azure_cli' | 'client_credentials' | 'basic';
  // Required for client_credentials auth
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  // Required for basic auth (on-prem)
  username?: string;
  password?: string;
}

export interface Company {
  id: string;
  systemVersion: string;
  timestamp: number;
  name: string;
  displayName: string;
  businessProfileId: string;
  systemCreatedAt: string;
  systemCreatedBy: string;
  systemModifiedAt: string;
  systemModifiedBy: string;
}

export class BusinessCentralClient {
  private config: BusinessCentralConfig;
  private companyId?: string;
  private credential?: TokenCredential;
  private basicAuthHeader?: string;

  constructor(config: BusinessCentralConfig) {
    this.config = config;

    if (config.authType === 'azure_cli') {
      this.credential = new AzureCliCredential();
    } else if (config.authType === 'client_credentials') {
      if (!config.tenantId || !config.clientId || !config.clientSecret) {
        throw new Error('client_credentials auth requires tenantId, clientId, and clientSecret');
      }
      this.credential = new ClientSecretCredential(
        config.tenantId,
        config.clientId,
        config.clientSecret
      );
    } else if (config.authType === 'basic') {
      if (!config.username || !config.password) {
        throw new Error('basic auth requires username and password');
      }
      this.basicAuthHeader = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString('base64')}`;
    }
  }

  /**
   * Get the company ID by looking up the company name
   */
  private async getCompanyId(): Promise<string> {
    if (this.companyId) {
      return this.companyId;
    }

    const url = `${this.config.serverUrl}/companies?$filter=name eq '${this.config.companyName}'`;
    const response = await this.request('GET', url);

    if (!response.value || response.value.length === 0) {
      throw new Error(`Company '${this.config.companyName}' not found`);
    }

    const companyId: string = response.value[0].id;
    this.companyId = companyId;
    return companyId;
  }

  /**
   * Make an authenticated request to Business Central API
   */
  private async request(method: string, url: string, body?: any): Promise<any> {
    let authHeader: string;

    if (this.basicAuthHeader) {
      authHeader = this.basicAuthHeader;
    } else if (this.credential) {
      const tokenResponse = await this.credential.getToken('https://api.businesscentral.dynamics.com/.default');
      if (!tokenResponse) {
        throw new Error('Failed to acquire access token');
      }
      authHeader = `Bearer ${tokenResponse.token}`;
    } else {
      throw new Error('Authentication not configured');
    }

    const headers: Record<string, string> = {
      'Authorization': authHeader,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const options: RequestInit = {
      method,
      headers,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Business Central API error (${response.status}): ${errorText}`);
    }

    return response.json();
  }

  /**
   * Get OData metadata for a resource
   */
  async getSchema(resource: string): Promise<any> {
    const companyId = await this.getCompanyId();
    const url = `${this.config.serverUrl}/companies(${companyId})/${resource}/$metadata`;
    return this.request('GET', url);
  }

  /**
   * List items from a resource with optional filtering and pagination
   */
  async listItems(resource: string, options?: {
    filter?: string;
    top?: number;
    skip?: number;
  }): Promise<any> {
    const companyId = await this.getCompanyId();
    let url = `${this.config.serverUrl}/companies(${companyId})/${resource}`;

    const params = new URLSearchParams();
    if (options?.filter) params.append('$filter', options.filter);
    if (options?.top) params.append('$top', options.top.toString());
    if (options?.skip) params.append('$skip', options.skip.toString());

    if (params.toString()) {
      url += `?${params.toString()}`;
    }

    return this.request('GET', url);
  }

  /**
   * Get items by field value
   */
  async getItemsByField(resource: string, field: string, value: string): Promise<any> {
    return this.listItems(resource, {
      filter: `${field} eq '${value}'`
    });
  }

  /**
   * Create a new item
   */
  async createItem(resource: string, data: any): Promise<any> {
    const companyId = await this.getCompanyId();
    const url = `${this.config.serverUrl}/companies(${companyId})/${resource}`;
    return this.request('POST', url, data);
  }

  /**
   * Update an existing item
   */
  async updateItem(resource: string, itemId: string, data: any): Promise<any> {
    const companyId = await this.getCompanyId();
    const url = `${this.config.serverUrl}/companies(${companyId})/${resource}(${itemId})`;
    return this.request('PATCH', url, data);
  }

  /**
   * Delete an item
   */
  async deleteItem(resource: string, itemId: string): Promise<void> {
    const companyId = await this.getCompanyId();
    const url = `${this.config.serverUrl}/companies(${companyId})/${resource}(${itemId})`;
    await this.request('DELETE', url);
  }
}
