import { apiClient } from './client';

export interface VerifyEmailRequest {
  token: string;
}

export interface VerifyEmailResponse {
  message: string;
  verified_at: string;
}

export interface ResendVerificationResponse {
  message: string;
}

export interface VerificationStatusResponse {
  email_verified: boolean;
  verified_at?: string;
}

export interface ErrorResponse {
  error: string;
}

export const emailVerificationApi = {
  /**
   * Verify email with token (public endpoint)
   */
  async verifyEmail(token: string): Promise<VerifyEmailResponse> {
    const response = await apiClient.post<VerifyEmailResponse>(
      '/api/idm/email/verify',
      { token }
    );
    return response.data;
  },

  /**
   * Resend verification email (authenticated endpoint)
   */
  async resendVerification(): Promise<ResendVerificationResponse> {
    const response = await apiClient.post<ResendVerificationResponse>(
      '/api/idm/email/resend',
      {}
    );
    return response.data;
  },

  /**
   * Get email verification status (authenticated endpoint)
   */
  async getVerificationStatus(): Promise<VerificationStatusResponse> {
    const response = await apiClient.get<VerificationStatusResponse>(
      '/api/idm/email/status'
    );
    return response.data;
  },
};
