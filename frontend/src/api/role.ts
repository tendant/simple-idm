import { apiClient } from './client';

export interface Role {
  uuid?: string;
  name?: string;
}

export const roleApi = {
  listRoles: async (): Promise<Role[]> => {
    const response = await apiClient('/api/roles');
    if (!response.ok) {
      throw new Error('Failed to fetch roles');
    }
    return response.json();
  },
};
