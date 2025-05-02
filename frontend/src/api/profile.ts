import { fetchWithAuth } from '../lib/fetch';
import { Device } from './device';

export interface ProfileResponse {
  status: string;
  message: string;
}

export interface ListDevicesResponse {
  status: string;
  message: string;
  devices: Device[];
}

export interface ProfileTwoFactorMethod {
  id: string;
  type: string;
  value: string;
  created_at: string;
  last_used_at?: string;
}

export interface DeviceWithLogin {
  fingerprint: string;
  user_agent: string;
  device_name: string;
  device_type: string;
  accept_headers?: string;
  timezone?: string;
  screen_resolution?: string;
  last_login: string;
  created_at: string;
  expires_at?: string;
  linked_logins?: Array<{
    id: string;
    username: string;
  }>;
}

export const profileApi = {
  /**
   * Get devices linked to the authenticated user's login
   * @returns Promise with the list of devices
   */
  async getMyDevices(): Promise<Device[]> {
    const response = await fetchWithAuth('/api/idm/profile/devices');
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch devices');
    }
    
    const data: ListDevicesResponse = await response.json();
    return data.devices || [];
  },

  async getTwoFactorMethods(): Promise<ProfileTwoFactorMethod[]> {
    const response = await fetchWithAuth('/api/v1/profile/2fa/methods');
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch 2FA methods');
    }
    const data = await response.json();
    return data.methods || [];
  },

  async addTwoFactorMethod(type: string, value: string): Promise<ProfileTwoFactorMethod> {
    const response = await fetchWithAuth('/api/v1/profile/2fa/methods', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type,
        value,
      }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to add 2FA method');
    }
    const data = await response.json();
    return data.method;
  },

  async removeTwoFactorMethod(id: string): Promise<void> {
    const response = await fetchWithAuth(`/api/v1/profile/2fa/methods/${id}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to remove 2FA method');
    }
  },

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const response = await fetchWithAuth('/api/v1/profile/password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to change password');
    }
  },

  /**
   * Update the display name of a device
   * @param fingerprint The fingerprint of the device
   * @param displayName The new display name
   * @returns Promise with the updated device
   */
  updateDeviceDisplayName: async (fingerprint: string, displayName: string): Promise<any> => {
    try {
      const response = await fetchWithAuth(`/api/idm/profile/devices/${fingerprint}/display-name`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ display_name: displayName }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to update device display name');
      }

      return await response.json();
    } catch (error) {
      console.error('Error updating device display name:', error);
      throw error;
    }
  },
};