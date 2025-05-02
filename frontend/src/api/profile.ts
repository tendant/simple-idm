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
  }
};
