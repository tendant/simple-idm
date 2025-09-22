import { apiClient } from './client';

export interface OAuth2Client {
  client_id: string;
  client_name: string;
  client_type: 'confidential' | 'public';
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  scope?: string;
  created_at: string;
  updated_at: string;
}

export interface OAuth2ClientRegistrationRequest {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  client_type?: 'confidential' | 'public';
  response_types?: string[];
  grant_types?: string[];
  scope?: string;
}

export interface OAuth2ClientUpdateRequest {
  client_name?: string;
  redirect_uris?: string[];
  client_type?: 'confidential' | 'public';
  response_types?: string[];
  grant_types?: string[];
  scope?: string;
}

export interface OAuth2ClientRegistrationResponse extends OAuth2Client {
  client_secret?: string;
}

export interface OAuth2ClientSecretResponse {
  client_id: string;
  client_secret: string;
  updated_at: string;
}

export interface OAuth2ClientListResponse {
  clients: OAuth2Client[];
  total: number;
  limit: number;
  offset: number;
}

export interface OAuth2ClientListParams {
  limit?: number;
  offset?: number;
  client_type?: 'confidential' | 'public';
  is_active?: boolean;
}

export const oauth2ClientApi = {
  async listClients(params?: OAuth2ClientListParams): Promise<OAuth2ClientListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    if (params?.client_type) searchParams.set('client_type', params.client_type);
    if (params?.is_active !== undefined) searchParams.set('is_active', params.is_active.toString());

    const url = `/api/idm/oauth2-clients${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const response = await apiClient.get(url);
    if (!response.ok) {
      throw new Error('Failed to fetch OAuth2 clients');
    }
    return response.json();
  },

  async getClient(clientId: string): Promise<OAuth2Client> {
    const response = await apiClient.get(`/api/idm/oauth2-clients/${clientId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch OAuth2 client');
    }
    return response.json();
  },

  async registerClient(client: OAuth2ClientRegistrationRequest): Promise<OAuth2ClientRegistrationResponse> {
    const response = await apiClient.post('/api/idm/oauth2-clients', client);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (errorData && errorData.message) {
        throw new Error(errorData.message);
      }
      throw new Error('Failed to register OAuth2 client');
    }
    return response.json();
  },

  async updateClient(clientId: string, updates: OAuth2ClientUpdateRequest): Promise<OAuth2Client> {
    const response = await apiClient.put(`/api/idm/oauth2-clients/${clientId}`, updates);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (errorData && errorData.message) {
        throw new Error(errorData.message);
      }
      throw new Error('Failed to update OAuth2 client');
    }
    return response.json();
  },

  async deleteClient(clientId: string): Promise<void> {
    const response = await apiClient.delete(`/api/idm/oauth2-clients/${clientId}`);
    if (!response.ok) {
      throw new Error('Failed to delete OAuth2 client');
    }
  },

  async regenerateClientSecret(clientId: string): Promise<OAuth2ClientSecretResponse> {
    const response = await apiClient.post(`/api/idm/oauth2-clients/${clientId}/regenerate-secret`, {});
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (errorData && errorData.message) {
        throw new Error(errorData.message);
      }
      throw new Error('Failed to regenerate client secret');
    }
    return response.json();
  },
};
