interface LoginRequest {
  username: string;
  password: string;
}

interface CreateUserRequest {
  username: string;
  password: string;
  name?: string;
  roles?: string[];
}

interface UpdateUserRequest {
  name?: string;
  password?: string;
  roles?: string[];
}

interface User {
  uuid: string;
  username: string;
  name?: string;
  roles?: Array<{
    uuid: string;
    name: string;
  }>;
}

export const userApi = {
  login: async (credentials: LoginRequest): Promise<User> => {
    const response = await fetch('/idm/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    return response.json();
  },

  listUsers: async (): Promise<User[]> => {
    const response = await fetch('/idm/users');
    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }
    return response.json();
  },

  createUser: async (user: CreateUserRequest): Promise<User> => {
    const response = await fetch('/idm/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(user),
    });

    if (!response.ok) {
      throw new Error('Failed to create user');
    }

    return response.json();
  },

  updateUser: async (uuid: string, user: UpdateUserRequest): Promise<User> => {
    const response = await fetch(`/idm/users/${uuid}`, {
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
    const response = await fetch(`/idm/users/${uuid}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete user');
    }
  },
};
