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
  last_modified_at: string;
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
  // List all devices
  async listDevices(): Promise<Device[]> {
    const response = await fetchWithAuth('/api/idm/device');
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch devices');
    }
    const data = await response.json();
    return data.devices || [];
  },

  // List devices linked to a specific login
  async listDevicesByLogin(loginId: string): Promise<Device[]> {
    const response = await fetchWithAuth(`/api/idm/device/login/${loginId}`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch devices for login');
    }
    const data = await response.json();
    return data.devices || [];
  },

  // Register a new device
  async registerDevice(fingerprint: string, userAgent?: string): Promise<Device> {
    const response = await fetchWithAuth('/api/idm/device/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fingerprint,
        user_agent: userAgent,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to register device');
    }
    
    const data = await response.json();
    return data.device;
  },

  // Link a device to a login
  async linkDevice(fingerprint: string, loginId?: string): Promise<{ expires_at: string }> {
    const response = await fetchWithAuth('/api/idm/device/link', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fingerprint,
        login_id: loginId,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to link device');
    }
    
    return response.json();
  },

  // Check device status
  async checkDeviceStatus(fingerprint: string): Promise<{ status: string; message: string }> {
    const response = await fetchWithAuth(`/api/idm/device/status/${fingerprint}`);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to check device status');
    }
    
    return response.json();
  },
};
