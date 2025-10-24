import { AzureCliCredential } from '@azure/identity';

export interface BusinessCentralConfig {
  serverUrl: string;
  companyName: string;
  authType: 'azure_cli';
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
  private credential?: AzureCliCredential;

  constructor(config: BusinessCentralConfig) {
    this.config = config;

    if (config.authType === 'azure_cli') {
      this.credential = new AzureCliCredential();
    }
  }

  /**
   * Get the company ID by looking up the company name
   */
  private async getCompanyId(): Promise<string> {
    if (this.companyId) {
      return this.companyId;
    }

    const url = `${this.config.serverUrl}/companies?$filter=displayName eq '${this.config.companyName}'`;
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
    if (!this.credential) {
      throw new Error('Authentication not configured');
    }

    // Get access token for Business Central
    const tokenResponse = await this.credential.getToken('https://api.businesscentral.dynamics.com/.default');

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${tokenResponse.token}`,
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
