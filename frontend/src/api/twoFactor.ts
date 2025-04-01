import { apiClient } from './client';

export interface TwoFactorSendRequest {
  email?: string;
  twofa_type: string;
  delivery_option?: string;
  user_id?: string;
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
  user_id?: string;
}

export interface TwoFactorMethod {
  type: string;
  delivery_options: DeliveryOption[];
  display_name?: string;
}

export interface ProfileTwoFactorMethod {
  two_factor_id: string;
  type: string;
  enabled: boolean;
}

export interface ProfileTwoFactorMethods {
  count: number;
  methods: ProfileTwoFactorMethod[];
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
    const response = await apiClient.post('/api/idm/auth/2fa/send', request, {
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
    const response = await apiClient.post('/api/idm/auth/2fa/validate', request, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    
    // Handle 202 status code for multiple_users
    if (response.status === 202) {
      const data = await response.json();
      if (data.status === 'multiple_users') {
        return {
          status: 'multiple_users',
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
    const response = await apiClient.post('/api/idm/idm/2fa/enable', {
      login_id: loginId,
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to enable ${twofaType} 2FA method`);
    }
  },

  disable2FAMethod: async (loginId: string, twofaType: string): Promise<void> => {
    const response = await apiClient.post('/api/idm/idm/2fa/disable', {
      login_id: loginId,
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to disable ${twofaType} 2FA method`);
    }
  },
  
  create2FAMethod: async (loginId: string, twofaType: string): Promise<void> => {
    const response = await apiClient.post('/api/idm/idm/2fa', {
      login_id: loginId,
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to create ${twofaType} 2FA method`);
    }
  },

  delete2FAMethod: async (loginId: string, twofaType: string, twofaId: string): Promise<void> => {
    const response = await apiClient.post('/api/idm/idm/2fa/delete', {
      login_id: loginId,
      twofa_type: twofaType,
      twofa_id: twofaId
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to delete ${twofaType} 2FA method`);
    }
  },

  setup2FAMethod: async (twofaType: string): Promise<any> => {
    const response = await apiClient.post('/api/idm/profile/2fa/setup', {
      twofa_type: twofaType
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `Failed to setup ${twofaType} 2FA method`);
    }
    
    return await response.json().catch(() => ({}));
  },
  
  get2FAMethods: async (): Promise<ProfileTwoFactorMethods> => {
    const response = await apiClient.get('/api/idm/profile/2fa');
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to get 2FA methods');
    }
    
    return await response.json();
  }
};
