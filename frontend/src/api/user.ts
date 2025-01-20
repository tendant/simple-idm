interface LoginRequest {
  email: string;
  password: string;
}

interface User {
  uuid: string;
  email: string;
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
};
