import { AzureCliCredential, ClientSecretCredential, TokenCredential } from '@azure/identity';

export interface BusinessCentralConfig {
  serverUrl: string;
  companyName: string;
  authType: 'azure_cli' | 'client_credentials';
  // Required for client_credentials auth
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
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
  private async request(method: string, url: string, body?: any, extraHeaders?: Record<string, string>): Promise<any> {
    if (!this.credential) {
      throw new Error('Authentication not configured');
    }

    // Get access token for Business Central
    const tokenResponse = await this.credential.getToken('https://api.businesscentral.dynamics.com/.default');

    if (!tokenResponse) {
      throw new Error('Failed to acquire access token');
    }

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${tokenResponse.token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...extraHeaders
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
    // Business Central enforces optimistic concurrency: PATCH requires an If-Match
    // header carrying the record's ETag. Use the @odata.etag from the supplied data
    // if present, otherwise '*' (match any current version). Strip the etag from the
    // body — BC reads it from the header, not the payload.
    const { '@odata.etag': bodyEtag, ...cleanData } = data ?? {};
    const ifMatch = typeof bodyEtag === 'string' && bodyEtag.length > 0 ? bodyEtag : '*';
    return this.request('PATCH', url, cleanData, { 'If-Match': ifMatch });
  }

  /**
   * Delete an item
   */
  async deleteItem(resource: string, itemId: string): Promise<void> {
    const companyId = await this.getCompanyId();
    const url = `${this.config.serverUrl}/companies(${companyId})/${resource}(${itemId})`;
    // DELETE also requires an If-Match header (optimistic concurrency); '*' matches
    // the current version.
    await this.request('DELETE', url, undefined, { 'If-Match': '*' });
  }
}
