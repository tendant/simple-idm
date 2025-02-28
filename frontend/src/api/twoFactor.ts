import { apiClient } from './client';

interface SendCodeRequest {
  method_type: string;
  delivery_option: string;
}

interface VerifyCodeRequest {
  method_type: string;
  code: string;
}

interface TwoFactorMethod {
  type: string;
  delivery_options: string[];
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
  roles?: Array<{
    id?: string;
    name?: string;
  }> | null;
}

export const twoFactorApi = {
  sendCode: async (tempToken: string, request: SendCodeRequest): Promise<void> => {
    const response = await apiClient('/auth/2fa/send-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tempToken}`
      },
      body: JSON.stringify(request),
      skipAuth: true,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to send verification code');
    }
  },

  verifyCode: async (tempToken: string, request: VerifyCodeRequest): Promise<User> => {
    const response = await apiClient('/auth/2fa/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tempToken}`
      },
      body: JSON.stringify(request),
      skipAuth: true,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Verification failed');
    }

    return response.json();
  }
};
