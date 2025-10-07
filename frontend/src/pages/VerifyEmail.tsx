import { Component, createSignal, onMount } from 'solid-js';
import { useNavigate, useSearchParams, A } from '@solidjs/router';
import { emailVerificationApi } from '../api/emailVerification';

const VerifyEmail: Component = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [status, setStatus] = createSignal<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = createSignal('');

  onMount(async () => {
    const token = searchParams.token;

    if (!token || typeof token !== 'string') {
      setStatus('error');
      setMessage('Invalid verification link. Please check your email and try again.');
      return;
    }

    try {
      const response = await emailVerificationApi.verifyEmail(token);
      setStatus('success');
      setMessage(response.message || 'Email verified successfully!');

      // Redirect to login after 3 seconds
      setTimeout(() => {
        navigate('/login');
      }, 3000);
    } catch (error: any) {
      setStatus('error');

      // Handle specific error messages
      const errorMessage = error?.response?.data?.error || error?.message || 'Failed to verify email';

      if (errorMessage.includes('expired')) {
        setMessage('Verification link has expired. Please request a new verification email.');
      } else if (errorMessage.includes('already been used')) {
        setMessage('This verification link has already been used. Your email is already verified.');
      } else if (errorMessage.includes('not found')) {
        setMessage('Invalid verification link. Please check your email and try again.');
      } else {
        setMessage(errorMessage);
      }
    }
  });

  return (
    <div class="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div class="max-w-md w-full space-y-8">
        <div>
          <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Email Verification
          </h2>
        </div>

        <div class="mt-8 bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          {status() === 'loading' && (
            <div class="text-center">
              <div class="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
              <p class="mt-4 text-gray-600">Verifying your email...</p>
            </div>
          )}

          {status() === 'success' && (
            <div class="text-center">
              <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                <svg
                  class="h-6 w-6 text-green-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <h3 class="mt-4 text-lg font-medium text-gray-900">Success!</h3>
              <p class="mt-2 text-sm text-gray-600">{message()}</p>
              <p class="mt-4 text-sm text-gray-500">
                Redirecting to login page in 3 seconds...
              </p>
              <div class="mt-6">
                <A
                  href="/login"
                  class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Go to Login
                </A>
              </div>
            </div>
          )}

          {status() === 'error' && (
            <div class="text-center">
              <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                <svg
                  class="h-6 w-6 text-red-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </div>
              <h3 class="mt-4 text-lg font-medium text-gray-900">Verification Failed</h3>
              <p class="mt-2 text-sm text-gray-600">{message()}</p>
              <div class="mt-6 space-y-4">
                <A
                  href="/login"
                  class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Go to Login
                </A>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail;
