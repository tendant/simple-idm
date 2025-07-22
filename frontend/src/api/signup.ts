import { apiClient } from './client';
import { User } from './user';

export interface PasswordlessSignupRequest {
  username?: string;
  email: string;
  fullname?: string;
  invitation_code?: string;
}

export interface SignupResponse {
  id?: string;
  username?: string;
  email?: string;
  message?: string;
  status?: string;
}

export const signupApi = {
  // Regular signup with password
  signup: async (data: { username: string; password: string; email: string; fullname: string; invitation_code?: string }): Promise<SignupResponse> => {
    const response = await apiClient.post('/api/idm/auth/signup', data, { skipAuth: true });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Signup failed');
    }
    return response.json();
  },

  // Passwordless signup
  passwordlessSignup: async (data: PasswordlessSignupRequest): Promise<SignupResponse> => {
    // Use the correct endpoint based on the backend implementation
    const response = await apiClient.post('/api/idm/signup/passwordless', data, { skipAuth: true });
    if (!response.ok) {
      // If the endpoint is not found, show a more helpful error message
      if (response.status === 404) {
        console.error('Passwordless signup endpoint not found. Make sure the backend API is properly configured.');
        throw new Error('Passwordless signup endpoint not available. This is a UI demo - the backend endpoint needs to be implemented.');
      }
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Passwordless signup failed');
    }
    return response.json();
  }
};
