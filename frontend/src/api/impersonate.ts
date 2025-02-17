import { apiClient } from './client';

export interface ImpersonateRequest {
  user_uuid: string;
}

export interface ImpersonateResponse {
  message: string;
  status: string;
  User: {
    user_uuid: string;
    delegatee_uuid: string;
    role: string[];
  };
}

export const impersonateApi = {
  createImpersonate: async (request: ImpersonateRequest): Promise<ImpersonateResponse> => {
    const response = await apiClient('/idm/impersonate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Failed to create impersonation');
    }

    return response.json();
  },
};
