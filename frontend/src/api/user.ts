import { apiClient } from './client';

interface LoginRequest {
  username: string;
  password: string;
}

interface DeliveryOption {
  display_value: string;
  hashed_value: string;
}

interface TwoFactorMethod {
  type: string;
  delivery_options: DeliveryOption[];
}

interface User {
  id: string;
  email: string;
  name: string;
  twoFactorEnabled?: boolean;
}

interface LoginResponse {
  id?: string;
  email?: string;
  username?: string;
  name?: string | null;
  created_at?: string;
  last_modified_at?: string;
  deleted_at?: string | null;
  created_by?: string | null;
  roles?: Array<{
    id?: string;
    name?: string;
  }> | null;
  // 2FA fields
  status?: string;
  message?: string;
  temp_token?: string;
  two_factor_methods?: TwoFactorMethod[];
  // User selection fields
  users?: User[];
}

interface CreateUserRequest {
  email: string;
  username: string;
  name?: string | null;
  role_ids?: string[];
  login_id?: string;
  password: string;
}

interface UpdateUserRequest {
  name?: string | null;
  username?: string;
  password?: string;
  role_ids?: string[];
  login_id?: string;
}

interface FindUsernameRequest {
  email: string;
}

interface User {
  id?: string;
  email?: string;
  username?: string;
  name?: string | null;
  created_at?: string;
  last_modified_at?: string;
  deleted_at?: string | null;
  created_by?: string | null;
  login_id?: string | null;
  roles?: Array<{
    id?: string;
    name?: string;
  }> | null;
}

export const userApi = {
  login: async (credentials: LoginRequest): Promise<LoginResponse> => {
    const response = await apiClient.post('/auth/login', credentials, { skipAuth: true });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Login failed');
    }

    return response.json();
  },

  listUsers: async (): Promise<User[]> => {
    const response = await apiClient.get('/idm/users');

    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }

    return response.json();
  },

  getUser: async (id: string): Promise<User> => {
    const response = await apiClient.get(`/idm/users/${id}`);

    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }

    return response.json();
  },

  createUser: async (user: CreateUserRequest): Promise<User> => {
    // Convert role_ids to the format expected by the backend
    const payload = {
      ...user,
      role_ids: user.role_ids?.map(id => id) || []
    };
    
    const response = await apiClient.post('/idm/users', payload);

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (errorData && errorData.message) {
        throw new Error(errorData.message);
      }
      throw new Error('Failed to create user');
    }

    return response.json();
  },

  updateUser: async (id: string, user: UpdateUserRequest): Promise<User> => {
    const response = await apiClient.put(`/idm/users/${id}`, user);

    if (!response.ok) {
      throw new Error('Failed to update user');
    }

    return response.json();
  },

  deleteUser: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/idm/users/${id}`);

    if (!response.ok) {
      throw new Error('Failed to delete user');
    }
  },

  findUsername: async (email: string): Promise<void> => {
    const response = await apiClient.post('/auth/find-username', { email }, { skipAuth: true });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to find username');
    }
  },

  switchUser: async (userId: string, token?: string): Promise<any> => {
    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await apiClient.post('/auth/user/switch', { user_id: userId }, { 
      headers,
      skipAuth: !!token // Skip default auth if we're providing a token
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to switch user');
    }

    return response.json();
  }
};
