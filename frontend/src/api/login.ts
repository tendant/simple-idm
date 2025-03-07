import { apiClient } from './client';

export interface Login {
  id?: string;
  username: string;
  created_at?: string;
  last_modified_at?: string;
  two_factor_enabled?: boolean;
  password_last_changed?: string;
  status?: string;
}

export interface TwoFactorMethod {
  type: string;
  enabled: boolean;
  two_factor_id: string;
}

export interface TwoFactorMethods {
  count: number;
  methods: TwoFactorMethod[] | null;
}

export interface CreateLoginRequest {
  username: string;
  password: string;
}

export interface UpdateLoginRequest {
  username?: string;
  password?: string;
  two_factor_enabled?: boolean;
}

export const loginApi = {
  listLogins: async (): Promise<Login[]> => {
    const response = await apiClient.get('/idm/logins');
    if (!response.ok) {
      throw new Error('Failed to fetch logins');
    }
    return response.json();
  },

  getLogin: async (id: string): Promise<Login> => {
    const response = await apiClient.get(`/idm/logins/${id}`);
    if (!response.ok) {
      throw new Error('Failed to fetch login');
    }
    return response.json();
  },

  createLogin: async (login: CreateLoginRequest): Promise<Login> => {
    const response = await apiClient.post('/idm/logins', login);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      if (errorData && errorData.message) {
        throw new Error(errorData.message);
      }
      throw new Error('Failed to create login');
    }
    return response.json();
  },

  updateLogin: async (id: string, login: UpdateLoginRequest): Promise<Login> => {
    const response = await apiClient.put(`/idm/logins/${id}`, login);
    if (!response.ok) {
      throw new Error('Failed to update login');
    }
    return response.json();
  },

  deleteLogin: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/idm/logins/${id}`);
    if (!response.ok) {
      throw new Error('Failed to delete login');
    }
  },

  resetPassword: async (id: string, newPassword: string): Promise<void> => {
    const response = await apiClient.post(`/idm/logins/${id}/reset-password`, { password: newPassword });
    if (!response.ok) {
      throw new Error('Failed to reset password');
    }
  },

  enable2FA: async (id: string): Promise<{ secret: string; qrCode: string }> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/enable`, {});
    if (!response.ok) {
      throw new Error('Failed to enable 2FA');
    }
    return response.json();
  },

  disable2FA: async (id: string, code: string): Promise<void> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/disable`, { code });
    if (!response.ok) {
      throw new Error('Failed to disable 2FA');
    }
  },

  verify2FA: async (id: string, code: string): Promise<boolean> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/verify`, { code });
    if (!response.ok) {
      throw new Error('Failed to verify 2FA code');
    }
    return response.json();
  },

  generateBackupCodes: async (id: string): Promise<string[]> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/backup-codes`, {});
    if (!response.ok) {
      throw new Error('Failed to generate backup codes');
    }
    return response.json();
  },
  
  get2FAMethods: async (id: string): Promise<TwoFactorMethods> => {
    const response = await apiClient.get(`/idm/logins/${id}/2fa`);
    if (!response.ok) {
      throw new Error('Failed to fetch 2FA methods');
    }
    return response.json();
  }
};
