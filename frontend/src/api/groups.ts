import { apiClient } from './client';

export interface Group {
  id?: string;
  name?: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
}

export interface CreateGroupRequest {
  name: string;
  description?: string;
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string;
}

export interface GroupUser {
  id?: string;
  email?: string;
  username?: string;
  name?: string;
}

export interface AddUserToGroupRequest {
  user_id: string;
}

export interface RemoveUserFromGroupRequest {
  user_id: string;
}

export const groupsApi = {
  listGroups: async (): Promise<Group[]> => {
    const response = await apiClient.get('/api/idm/users/groups');

    if (!response.ok) {
      throw new Error('Failed to fetch groups');
    }

    return response.json();
  },

  getGroup: async (id: string): Promise<Group> => {
    const response = await apiClient.get(`/api/idm/users/groups/${id}`);

    if (!response.ok) {
      throw new Error('Failed to fetch group');
    }

    return response.json();
  },

  createGroup: async (group: CreateGroupRequest): Promise<Group> => {
    try {
      const response = await apiClient.post('/api/idm/users/groups', group);

      if (!response.ok) {
        // Try to parse the error response
        const errorData = await response.json().catch(() => null);
        
        // Handle specific error cases based on status code
        if (response.status === 400) {
          if (errorData?.message?.includes('name')) {
            throw new Error(`Name error: ${errorData.message}`);
          } else if (errorData?.message) {
            throw new Error(errorData.message);
          }
          throw new Error('Invalid group data provided');
        } else if (response.status === 409) {
          throw new Error('A group with this name already exists');
        } else if (response.status === 403) {
          throw new Error('You do not have permission to create groups');
        } else if (response.status === 501) {
          throw new Error('Groups are not supported on this server');
        } else if (response.status === 500) {
          throw new Error('Server error occurred while creating group');
        }
        
        // Generic error with message if available
        if (errorData && errorData.message) {
          throw new Error(errorData.message);
        }
        throw new Error(`Failed to create group (Status: ${response.status})`);
      }

      return response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('An unexpected error occurred while creating group');
    }
  },

  updateGroup: async (id: string, group: UpdateGroupRequest): Promise<Group> => {
    const response = await apiClient.put(`/api/idm/users/groups/${id}`, group);

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (response.status === 501) {
        throw new Error('Groups are not supported on this server');
      }
      throw new Error(errorData?.message || 'Failed to update group');
    }

    return response.json();
  },

  deleteGroup: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/api/idm/users/groups/${id}`);

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (response.status === 501) {
        throw new Error('Groups are not supported on this server');
      }
      throw new Error(errorData?.message || 'Failed to delete group');
    }
  },

  getGroupUsers: async (id: string): Promise<GroupUser[]> => {
    const response = await apiClient.get(`/api/idm/users/groups/${id}/users`);

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (response.status === 501) {
        throw new Error('Groups are not supported on this server');
      }
      throw new Error(errorData?.message || 'Failed to fetch group users');
    }

    return response.json();
  },

  addUserToGroup: async (groupId: string, userId: string): Promise<void> => {
    const response = await apiClient.post(`/api/idm/users/groups/${groupId}/users`, {
      user_id: userId
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (response.status === 501) {
        throw new Error('Groups are not supported on this server');
      }
      throw new Error(errorData?.message || 'Failed to add user to group');
    }
  },

  removeUserFromGroup: async (groupId: string, userId: string): Promise<void> => {
    const response = await apiClient.call(`/api/idm/users/groups/${groupId}/users`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user_id: userId })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (response.status === 501) {
        throw new Error('Groups are not supported on this server');
      }
      throw new Error(errorData?.message || 'Failed to remove user from group');
    }
  }
};
