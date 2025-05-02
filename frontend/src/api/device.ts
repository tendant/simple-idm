import { fetchWithAuth } from '../lib/fetch';

export interface LoginInfo {
  id: string;
  username: string;
}

export interface Device {
  id?: string;
  fingerprint: string;
  user_agent: string;
  last_login: string;
  created_at: string;
  last_modified_at?: string;
  linked_logins?: LoginInfo[];
  expires_at?: string; // When the device-login link expires
}

export interface LoginDevice {
  id?: string;
  login_id: string;
  device_fingerprint: string;
  created_at: string;
  expires_at: string;
}

export const deviceApi = {

  // List devices linked to a specific login
  async listDevicesByLogin(loginId: string): Promise<Device[]> {
    const response = await fetchWithAuth(`/api/idm/device/login/${loginId}`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch devices for login');
    }
    const data = await response.json();
    
    // Map the API response to the expected format
    return (data.devices || []).map((device: any) => ({
      fingerprint: device.Fingerprint,
      user_agent: device.UserAgent,
      last_login: device.LastLoginAt,
      created_at: device.CreatedAt,
      linked_logins: device.linked_logins,
      expires_at: device.expires_at
    }));
  },

  // Unlink a device from a login
  async unlinkDeviceFromLogin(loginId: string, fingerprint: string): Promise<void> {
    const response = await fetchWithAuth(`/api/idm/device/login/${loginId}/unlink`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fingerprint,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to unlink device from login');
    }
  },
};
