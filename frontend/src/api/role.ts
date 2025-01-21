import { apiClient } from './client';

export interface Role {
  uuid: string;
  name: string;
}

export interface CreateRoleRequest {
  name: string;
}

export interface UpdateRoleRequest {
  name: string;
}

export const roleApi = {
  listRoles: async (): Promise<Role[]> => {
    const response = await apiClient('/idm/roles');
    if (!response.ok) {
      throw new Error('Failed to fetch roles');
    }
    return response.json();
  },

  getRole: async (uuid: string): Promise<Role> => {
    console.log('Fetching role with UUID:', uuid);
    const response = await apiClient(`/idm/roles/${uuid}`);
    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    if (!response.ok) {
      console.error('Failed to fetch role:', response.status, response.statusText);
      throw new Error('Failed to fetch role');
    }

    const data = await response.json();
    console.log('Response data:', JSON.stringify(data, null, 2));
    return data;
  },

  createRole: async (role: CreateRoleRequest): Promise<Role> => {
    const response = await apiClient('/idm/roles', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(role),
    });

    if (!response.ok) {
      throw new Error('Failed to create role');
    }
    return response.json();
  },

  updateRole: async (uuid: string, role: UpdateRoleRequest): Promise<Role> => {
    const response = await apiClient(`/idm/roles/${uuid}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(role),
    });

    if (!response.ok) {
      throw new Error('Failed to update role');
    }
    return response.json();
  },

  deleteRole: async (uuid: string): Promise<void> => {
    const response = await apiClient(`/idm/roles/${uuid}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete role');
    }
  },
};
