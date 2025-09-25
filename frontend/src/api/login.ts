import { apiClient } from './client';
import { LoginResponse } from './user';

export interface Login {
  id?: string;
  username: string;
  created_at?: string;
  last_modified_at?: string;
  two_factor_enabled?: boolean;
  password_last_changed?: string;
  status?: string;
  is_passwordless?: boolean;
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
  email?: string; // Added to support email in login creation
}

export interface UpdateLoginRequest {
  username?: string;
  password?: string;
  two_factor_enabled?: boolean;
}

export interface PasswordPolicyResponse {
  min_length?: number;
  require_uppercase?: boolean;
  require_lowercase?: boolean;
  require_digit?: boolean;
  require_special_char?: boolean;
  disallow_common_pwds?: boolean;
  max_repeated_chars?: number;
  history_check_count?: number;
  expiration_days?: number;
}

export const loginApi = {
  listLogins: async (): Promise<Login[]> => {
    const response = await apiClient.get('/api/idm/logins');
    if (!response.ok) {
      throw new Error('Failed to fetch logins');
    }
    return response.json();
  },

  // Magic link login methods
  requestMagicLink: async (username: string): Promise<{ message: string }> => {
    const response = await apiClient.post('/api/idm/auth/login/magic-link', { username }, { skipAuth: true });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to request magic link');
    }
    return response.json();
  },

  validateMagicLink: async (token: string): Promise<LoginResponse> => {
    const response = await apiClient.get(`/api/idm/auth/login/magic-link/validate?token=${encodeURIComponent(token)}`, { skipAuth: true });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Invalid or expired magic link');
    }
    return response.json();
  },

  getLogin: async (id: string): Promise<Login> => {
    const response = await apiClient.get(`/api/idm/logins/${id}`);
    if (!response.ok) {
      throw new Error('Failed to fetch login');
    }
    return response.json();
  },

  createLogin: async (login: CreateLoginRequest): Promise<Login> => {
    const response = await apiClient.post('/api/idm/logins', login);
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
    const response = await apiClient.put(`/api/idm/logins/${id}`, login);
    if (!response.ok) {
      throw new Error('Failed to update login');
    }
    return response.json();
  },

  deleteLogin: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/api/idm/logins/${id}`);
    if (!response.ok) {
      throw new Error('Failed to delete login');
    }
  },

  resetPassword: async (id: string, newPassword: string): Promise<void> => {
    const response = await apiClient.post(`/api/idm/logins/${id}/reset-password`, { password: newPassword });
    if (!response.ok) {
      throw new Error('Failed to reset password');
    }
  },

  enable2FA: async (id: string): Promise<{ secret: string; qrCode: string }> => {
    const response = await apiClient.post(`/api/idm/logins/${id}/2fa/enable`, {});
    if (!response.ok) {
      throw new Error('Failed to enable 2FA');
    }
    return response.json();
  },

  disable2FA: async (id: string, code: string): Promise<void> => {
    const response = await apiClient.post(`/api/idm/logins/${id}/2fa/disable`, { code });
    if (!response.ok) {
      throw new Error('Failed to disable 2FA');
    }
  },

  verify2FA: async (id: string, code: string): Promise<boolean> => {
    const response = await apiClient.post(`/api/idm/logins/${id}/2fa/verify`, { code });
    if (!response.ok) {
      throw new Error('Failed to verify 2FA code');
    }
    return response.json();
  },

  generateBackupCodes: async (id: string): Promise<string[]> => {
    const response = await apiClient.post(`/api/idm/logins/${id}/2fa/backup-codes`, {});
    if (!response.ok) {
      throw new Error('Failed to generate backup codes');
    }
    return response.json();
  },
  
  get2FAMethods: async (id: string): Promise<TwoFactorMethods> => {
    const response = await apiClient.get(`/api/idm/logins/${id}/2fa`);
    if (!response.ok) {
      throw new Error('Failed to fetch 2FA methods');
    }
    return response.json();
  },

  getPasswordResetPolicy: async (token: string): Promise<PasswordPolicyResponse> => {
    const response = await apiClient.get(`/api/idm/auth/password/reset/policy?token=${encodeURIComponent(token)}`, { skipAuth: true });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to fetch password policy');
    }
    return response.json();
  }
};
