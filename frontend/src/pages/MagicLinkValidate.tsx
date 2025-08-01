import { Component, createSignal, onMount } from 'solid-js';
import { useNavigate, useSearchParams } from '@solidjs/router';
import { loginApi } from '../api/login';

const MagicLinkValidate: Component = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  onMount(async () => {
    const tokenParam = searchParams.token;
    
    if (!tokenParam) {
      setError('No token provided. Please request a new magic link.');
      setLoading(false);
      return;
    }
    
    // Handle both string and string[] cases
    const token = Array.isArray(tokenParam) ? tokenParam[0] : tokenParam;

    try {
      const response = await loginApi.validateMagicLink(token);
      
      // Check if user selection is required
      if (response.status === 'multiple_users') {
        // Redirect to the TwoFactorVerification page with user selection mode
        const params = new URLSearchParams();
        if (response.temp_token) {
          params.set('token', response.temp_token);
        }
        params.set('user_selection_required', 'true');
        
        // Pass the users array to the verification page
        if (response.users && Array.isArray(response.users)) {
          params.set('users', encodeURIComponent(JSON.stringify(response.users)));
        }
        
        navigate(`/two-factor-verification?${params.toString()}`);
        return;
      }
      
      // Store the user info in localStorage
      localStorage.setItem('user', JSON.stringify(response));

      // Redirect to the users page
      navigate('/users');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid or expired magic link');
    } finally {
      setLoading(false);
    }
  });

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          Magic Link Login
        </h2>
      </div>

      <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow-lg rounded-lg sm:px-10">
          {loading() && (
            <div class="text-center py-4">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-600"></div>
              <p class="mt-2 text-gray-11">Validating your magic link...</p>
            </div>
          )}

          {error() && !loading() && (
            <div class="rounded-lg bg-red-2 p-4 mb-6">
              <div class="flex">
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-red-11">{error()}</h3>
                  <div class="mt-4">
                    <button
                      type="button"
                      onClick={() => navigate('/magic-link-login')}
                      class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    >
                      Request a new magic link
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MagicLinkValidate;
