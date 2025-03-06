import { apiClient } from './client';

export interface TwoFactorSendRequest {
  email?: string;
  twofa_type: string;
  delivery_option?: string;
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

export interface DeliveryOption {
  display_value: string;
  hashed_value: string;
}

export interface TwoFactorMethod {
  type: string;
  delivery_options: DeliveryOption[];
  display_name?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
}

export interface SelectUserRequiredResponse {
  status: string;
  message: string;
  temp_token: string;
  users: User[];
}

export const twoFactorApi = {
  sendCode: async (token: string, request: TwoFactorSendRequest): Promise<void> => {
    const response = await apiClient.post('/idm/2fa/send', request, {
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
    const response = await apiClient.post('/idm/2fa/validate', request, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    
    // Handle 202 status code for select_user_required
    if (response.status === 202) {
      const data = await response.json();
      if (data.status === 'select_user_required') {
        return {
          status: 'select_user_required',
          message: data.message,
          temp_token: data.temp_token,
          users: data.users
        };
      }
    }
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Verification failed');
    }
    
    try {
      return await response.json();
    } catch (e) {
      return { success: true };
    }
  },

  enable2FAMethod: async (loginId: string, twofaType: string): Promise<void> => {
    const response = await apiClient.post('/idm/2fa/enable', {
      login_id: loginId,
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to enable ${twofaType} 2FA method`);
    }
  },

  disable2FAMethod: async (loginId: string, twofaType: string): Promise<void> => {
    const response = await apiClient.post('/idm/2fa/disable', {
      login_id: loginId,
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to disable ${twofaType} 2FA method`);
    }
  }
};
