import { apiClient } from './client';

export interface Role {
  id: string;
  name: string;
}

export interface CreateRoleRequest {
  name: string;
}

export interface UpdateRoleRequest {
  name: string;
}

export interface RoleUser {
  id?: string;
  email?: string;
  name?: string;
  username?: string;
}

export const roleApi = {
  listRoles: async (): Promise<Role[]> => {
    const response = await apiClient('/idm/roles');
    if (!response.ok) {
      throw new Error('Failed to fetch roles');
    }
    return response.json();
  },

  getRole: async (id: string): Promise<Role> => {
    console.log('Fetching role with ID:', id);
    const response = await apiClient(`/idm/roles/${id}`);
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

  getRoleUsers: async (id: string): Promise<RoleUser[]> => {
    const response = await apiClient(`/idm/roles/${id}/users`);
    if (!response.ok) {
      throw new Error('Failed to fetch role users');
    }
    return response.json();
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

  updateRole: async (id: string, role: UpdateRoleRequest): Promise<Role> => {
    const response = await apiClient(`/idm/roles/${id}`, {
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

  deleteRole: async (id: string): Promise<void> => {
    const response = await apiClient(`/idm/roles/${id}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete role');
    }
  },

  removeUserFromRole: async (roleId: string, userId: string): Promise<void> => {
    const response = await apiClient(`/idm/roles/${roleId}/users/${userId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error('Failed to remove user from role');
    }
  },
};
