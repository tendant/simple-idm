import { apiClient } from './client';

export interface TwoFactorSendRequest {
  email: string;
  twofa_type: string;
}

export interface TwoFactorVerifyRequest {
  twofa_type: string;
  passcode: string;
}

export interface UserData {
  id: string;
  username: string;
  email: string;
  role: string;
  token: string;
}

export interface TwoFactorMethod {
  type: string;
  delivery_options: string[];
}

export interface User {
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
  sendCode: async (token: string, request: TwoFactorSendRequest): Promise<void> => {
    const response = await apiClient.post('/idm/twofa/2fa/send', request, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to send verification code');
    }
  },
  
  verifyCode: async (token: string, request: TwoFactorVerifyRequest): Promise<any> => {
    const response = await apiClient.post('/idm/twofa/2fa/validate', request, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Verification failed');
    }
    
    try {
      return await response.json();
    } catch (e) {
      return { success: true };
    }
  }
};
