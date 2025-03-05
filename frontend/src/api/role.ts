import { apiClient } from './client';

export interface Role {
  id?: string;
  uuid?: string;
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
  uuid?: string;
  email?: string;
  name?: string;
  username?: string;
}

export const roleApi = {
  listRoles: async (): Promise<Role[]> => {
    const response = await apiClient.get('/idm/roles');
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to fetch roles');
    }
    const roles = await response.json();
    
    // Ensure each role has an id property (use uuid if available)
    return roles.map((role: any) => ({
      ...role,
      id: role.uuid || role.id
    }));
  },

  getRole: async (id: string): Promise<Role> => {
    console.log('Fetching role with ID:', id);
    const response = await apiClient.get(`/idm/roles/${id}`);
    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      console.error('Failed to fetch role:', response.status, response.statusText);
      throw new Error('Failed to fetch role');
    }

    const data = await response.json();
    console.log('Response data:', JSON.stringify(data, null, 2));
    
    // Ensure the role has an id property (use uuid if available)
    return {
      ...data,
      id: data.uuid || data.id
    };
  },

  getRoleUsers: async (id: string): Promise<RoleUser[]> => {
    const response = await apiClient.get(`/idm/roles/${id}/users`);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to fetch role users');
    }
    return response.json();
  },

  createRole: async (role: CreateRoleRequest): Promise<Role> => {
    const response = await apiClient.post('/idm/roles', role);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to create role');
    }
    return response.json();
  },

  updateRole: async (id: string, role: UpdateRoleRequest): Promise<Role> => {
    console.log('API: Updating role with ID:', id);
    console.log('API: Update payload:', JSON.stringify(role));
    
    const response = await apiClient.put(`/idm/roles/${id}`, role);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    console.log('API: Update response status:', response.status);
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      const errorText = await response.text();
      console.error('API: Failed to update role:', errorText);
      throw new Error(`Failed to update role: ${errorText}`);
    }
    
    const data = await response.json();
    console.log('API: Update response data:', JSON.stringify(data));
    
    // Ensure the role has an id property (use uuid if available)
    return {
      ...data,
      id: data.uuid || data.id
    };
  },

  deleteRole: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/idm/roles/${id}`);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to delete role');
    }
  },

  removeUserFromRole: async (roleId: string, userId: string): Promise<void> => {
    const response = await apiClient.delete(`/idm/roles/${roleId}/users/${userId}`);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to remove user from role');
    }
  },
};
