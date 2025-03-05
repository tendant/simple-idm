import { apiClient } from './client';

export interface Login {
  id?: string;
  username: string;
  email?: string;
  created_at?: string;
  last_modified_at?: string;
  two_factor_enabled?: boolean;
  password_last_changed?: string;
  status?: string;
}

export interface CreateLoginRequest {
  username: string;
  email?: string;
  password: string;
}

export interface UpdateLoginRequest {
  username?: string;
  email?: string;
  password?: string;
  two_factor_enabled?: boolean;
}

export const loginApi = {
  listLogins: async (): Promise<Login[]> => {
    const response = await apiClient.get('/idm/logins');
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to fetch logins');
    }
    return response.json();
  },

  getLogin: async (id: string): Promise<Login> => {
    const response = await apiClient.get(`/idm/logins/${id}`);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error(`Failed to fetch login with ID: ${id}`);
    }
    return response.json();
  },

  createLogin: async (login: CreateLoginRequest): Promise<Login> => {
    const response = await apiClient.post('/idm/logins', login);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to create login');
    }
    return response.json();
  },

  updateLogin: async (id: string, login: UpdateLoginRequest): Promise<Login> => {
    const response = await apiClient.put(`/idm/logins/${id}`, login);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to update login');
    }
    return response.json();
  },

  deleteLogin: async (id: string): Promise<void> => {
    const response = await apiClient.delete(`/idm/logins/${id}`);
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to delete login');
    }
  },

  resetPassword: async (id: string, newPassword: string): Promise<void> => {
    const response = await apiClient.post(`/idm/logins/${id}/reset-password`, { password: newPassword });
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to reset password');
    }
  },

  enable2FA: async (id: string): Promise<{ secret: string; qrCode: string }> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/enable`, {});
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to enable 2FA');
    }
    return response.json();
  },

  disable2FA: async (id: string, code: string): Promise<void> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/disable`, { code });
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to disable 2FA');
    }
  },

  verify2FA: async (id: string, code: string): Promise<boolean> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/verify`, { code });
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to verify 2FA code');
    }
    return response.json();
  },

  generateBackupCodes: async (id: string): Promise<string[]> => {
    const response = await apiClient.post(`/idm/logins/${id}/2fa/backup-codes`, {});
    
    // Check for permission error
    if ((response as any).isPermissionError) {
      throw new Error('No permission');
    }
    
    if (!response.ok) {
      if (response.status === 403) {
        const data = await response.json();
        throw new Error(data.message || 'No permission');
      }
      throw new Error('Failed to generate backup codes');
    }
    return response.json();
  },
};
