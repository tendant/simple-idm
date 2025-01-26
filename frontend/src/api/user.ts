import { apiClient } from './client';

interface LoginRequest {
  username: string;
  password: string;
}

interface CreateUserRequest {
  email: string;
  username: string;
  name?: string | null;
  role_uuids?: string[];
}

interface UpdateUserRequest {
  name?: string | null;
  username?: string;
  password?: string;
  role_uuids?: string[];
}

interface FindUsernameRequest {
  email: string;
}

interface User {
  uuid?: string;
  email?: string;
  username?: string;
  name?: string | null;
  created_at?: string;
  last_modified_at?: string;
  deleted_at?: string | null;
  created_by?: string | null;
  roles?: Array<{
    uuid?: string;
    name?: string;
  }> | null;
}

export const userApi = {
  login: async (credentials: LoginRequest): Promise<User> => {
    const response = await apiClient('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
      skipAuth: true,
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    return response.json();
  },

  listUsers: async (): Promise<User[]> => {
    const response = await apiClient('/idm/users');

    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }

    return response.json();
  },

  getUser: async (uuid: string): Promise<User> => {
    const response = await apiClient(`/idm/users/${uuid}`);

    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }

    return response.json();
  },

  createUser: async (user: CreateUserRequest): Promise<User> => {
    const response = await apiClient('/idm/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: user.email,
        username: user.username,
        name: user.name || null,
        role_uuids: user.role_uuids || []
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Failed to create user');
    }

    return response.json();
  },

  updateUser: async (uuid: string, user: UpdateUserRequest): Promise<User> => {
    const response = await apiClient(`/idm/users/${uuid}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(user),
    });

    if (!response.ok) {
      throw new Error('Failed to update user');
    }

    return response.json();
  },

  deleteUser: async (uuid: string): Promise<void> => {
    const response = await apiClient(`/idm/users/${uuid}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete user');
    }
  },

  findUsername: async (email: string): Promise<void> => {
    const response = await apiClient('/auth/username/find', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email }),
      skipAuth: true,
    });

    if (!response.ok) {
      throw new Error('Failed to find username');
    }
  },
};
