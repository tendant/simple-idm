import { fetchWithAuth } from '../lib/fetch';
import { Device } from './device';
import { PasswordPolicyResponse } from './login';

export interface ProfileResponse {
  status: string;
  message: string;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  phone_number?: string;
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
   * Get the user's profile information
   * @returns Promise with the user's profile information
   */
  async getProfile(): Promise<UserProfile[]> {
    const response = await fetchWithAuth('/api/idm/profile/users');
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch profile information');
    }
    
    const data = await response.json();
    return data.users || [];
  },
  
  /**
   * Get the user's phone number
   * @returns Promise with the user's phone number
   */
  async getPhone(): Promise<{ phone: string }> {
    const response = await fetchWithAuth('/api/idm/profile/phone');
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch phone number');
    }
    
    return await response.json();
  },
  /**
   * Update phone number
   * @param phone The phone number to update
   * @returns Promise with the response
   */
  async updatePhone(phone: string): Promise<ProfileResponse> {
    const response = await fetchWithAuth('/api/idm/profile/phone', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ phone }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to update phone number');
    }
    
    return await response.json();
  },

  /**
   * Send phone verification code
   * @param phone The phone number to send verification code to
   * @returns Promise with the response
   */
  async sendPhoneVerification(phone: string): Promise<ProfileResponse> {
    const response = await fetchWithAuth('/api/idm/profile/phone/verify/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ phone }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to send verification code');
    }
    
    return await response.json();
  },

  /**
   * Verify phone with code
   * @param phone The phone number to verify
   * @param code The verification code
   * @returns Promise with the response
   */
  async verifyPhone(phone: string, code: string): Promise<ProfileResponse> {
    const response = await fetchWithAuth('/api/idm/profile/phone/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ phone, code }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to verify phone number');
    }
    
    return await response.json();
  },

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
    return (data.devices || []).map((device: any) => ({
      fingerprint: device.fingerprint,
      user_agent: device.user_agent,
      device_name: device.device_name,
      device_type: device.device_type,
      display_name: device.display_name,
      last_login: device.last_login_at,
      created_at: device.created_at,
      linked_logins: device.linked_logins,
      expires_at: device.expires_at
    }));
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
  
  /**
   * Unlink a device from the current login
   * @param fingerprint The fingerprint of the device to unlink
   * @returns Promise with the response
   */
  unlinkDevice: async (fingerprint: string): Promise<ProfileResponse> => {
    try {
      const response = await fetchWithAuth('/api/idm/profile/devices/unlink', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ fingerprint }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to unlink device');
      }

      return await response.json();
    } catch (error) {
      console.error('Error unlinking device:', error);
      throw error;
    }
  },

  /**
   * Get password policy for profile settings
   * @returns Promise with the password policy
   */
  async getPasswordPolicy(): Promise<PasswordPolicyResponse> {
    const response = await fetchWithAuth('/api/idm/profile/password/policy');
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.message || 'Failed to fetch password policy');
    }
    
    return response.json();
  },
};
