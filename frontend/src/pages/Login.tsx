import { Component, createSignal, onMount, createResource, For, Show } from 'solid-js';
import { useNavigate, useSearchParams, A } from '@solidjs/router';
import { userApi } from '../api/user';
import { DeliveryOption } from '../api/twoFactor';
import { getExternalProviders, initiateOAuth2Flow, handleOAuth2Callback, type ExternalProvider } from '../api/externalProviders';
import { needsFullRedirect } from '../lib/utils';

const Login: Component = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [authMessage, setAuthMessage] = createSignal<{ success: boolean; message: string } | null>(null);

  // Load external providers
  const [externalProviders] = createResource(getExternalProviders);

  // Handle OAuth2 callback on component mount
  onMount(() => {
    const callback = handleOAuth2Callback();
    if (callback.success || callback.message !== 'No authentication callback detected.') {
      setAuthMessage(callback);
      
      // If successful, redirect after a short delay
      if (callback.success) {
        setTimeout(() => {
          const redirectPath = searchParams.redirect || '/users';
          navigate(Array.isArray(redirectPath) ? redirectPath[0] : redirectPath);
        }, 2000);
      }
    }
  });

  const handleExternalProviderLogin = (providerId: string) => {
    const redirectUrl = searchParams.redirect 
      ? (Array.isArray(searchParams.redirect) ? searchParams.redirect[0] : searchParams.redirect)
      : '/users';
    
    initiateOAuth2Flow(providerId, redirectUrl);
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await userApi.login({
        username: username(),
        password: password(),
      });

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
        
        if (searchParams.redirect) {
          // Handle both string and string[] cases
          const redirectParam = Array.isArray(searchParams.redirect) 
            ? searchParams.redirect[0] 
            : searchParams.redirect;
          params.set('redirect', redirectParam);
        }
        
        navigate(`/two-factor-verification?${params.toString()}`);
        return;
      }
      
      // Check if 2FA is required
      if (response.status === '2fa_required') {
        // Redirect to 2FA verification page with necessary params
        const params = new URLSearchParams();
        if (response.temp_token) {
          params.set('token', response.temp_token);
        }
        
        // Ensure two_factor_methods is properly formatted before passing it
        if (response.two_factor_methods && Array.isArray(response.two_factor_methods)) {
          // Properly format the methods to match our interface
          const formattedMethods = response.two_factor_methods.map(method => ({
            type: method.type,
            delivery_options: method.delivery_options || [],
            display_name: method.type === 'email' ? 'Email' : method.type
          }));
          
          params.set('methods', encodeURIComponent(JSON.stringify(formattedMethods)));
        }
        
        if (searchParams.redirect) {
          // Handle both string and string[] cases
          const redirectParam = Array.isArray(searchParams.redirect) 
            ? searchParams.redirect[0] 
            : searchParams.redirect;
          params.set('redirect', redirectParam);
        }
        navigate(`/two-factor-verification?${params.toString()}`);
        return;
      }

      // Regular login flow (no 2FA)
      // Store the user info in localStorage
      localStorage.setItem('user', JSON.stringify(response));

      // Redirect to the original page or default to /users
      let redirectPath = '/users';
      if (searchParams.redirect) {
        console.log("searchParams.redirect to:", searchParams.redirect);
        redirectPath = Array.isArray(searchParams.redirect)
          ? searchParams.redirect[0]
          : searchParams.redirect;
      }
      console.log("Redirecting to:", redirectPath);

      // Use utility function to determine redirect strategy
      if (needsFullRedirect(redirectPath)) {
        // Use full page redirect for external URLs or backend endpoints
        window.location.href = redirectPath;
      } else {
        // Use frontend router for internal routes
        navigate(redirectPath);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          Sign in to your account
        </h2>
      </div>

      <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow-lg rounded-lg sm:px-10">
          <form class="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label
                for="username"
                class="block text-sm font-medium text-gray-11"
              >
                Username
              </label>
              <div class="mt-1">
                <input
                  id="username"
                  name="username"
                  type="text"
                  autocomplete="username"
                  required
                  value={username()}
                  onInput={(e) => setUsername(e.currentTarget.value)}
                  class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                />
              </div>
            </div>

            <div>
              <label
                for="password"
                class="block text-sm font-medium text-gray-11"
              >
                Password
              </label>
              <div class="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autocomplete="current-password"
                  required
                  value={password()}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                  class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                />
              </div>
            </div>

            {error() && (
              <div class="rounded-lg bg-red-2 p-4">
                <div class="flex">
                  <div class="ml-3">
                    <h3 class="text-sm font-medium text-red-11">{error()}</h3>
                  </div>
                </div>
              </div>
            )}

            <div>
              <button
                type="submit"
                disabled={loading()}
                class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading() ? 'Signing in...' : 'Sign in'}
              </button>
            </div>
            <div class="text-center">
              <div class="flex justify-center space-x-4">
                <A
                  href="/password-reset-init"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Forgot your password?
                </A>
                <span class="text-gray-8">•</span>
                <A
                  href="/find-username"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Forgot your username?
                </A>
              </div>
              <div class="mt-4 flex justify-center space-x-4">
                <A
                  href="/magic-link-login"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Login with magic link
                </A>
                <span class="text-gray-8">•</span>
                <A
                  href="/passwordless-signup"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Sign up without password
                </A>
              </div>
            </div>
          </form>

          {/* OAuth2 Authentication Message */}
          <Show when={authMessage()}>
            <div class={`mt-4 rounded-lg p-4 ${authMessage()?.success ? 'bg-green-2' : 'bg-red-2'}`}>
              <div class="flex">
                <div class="ml-3">
                  <h3 class={`text-sm font-medium ${authMessage()?.success ? 'text-green-11' : 'text-red-11'}`}>
                    {authMessage()?.message}
                  </h3>
                </div>
              </div>
            </div>
          </Show>

          {/* External Provider Login Buttons */}
          <Show when={externalProviders() && externalProviders()!.length > 0}>
            <div class="mt-6">
              <div class="relative">
                <div class="absolute inset-0 flex items-center">
                  <div class="w-full border-t border-gray-300" />
                </div>
                <div class="relative flex justify-center text-sm">
                  <span class="px-2 bg-white text-gray-500">Or continue with</span>
                </div>
              </div>

              <div class="mt-6 space-y-3">
                <For each={externalProviders()}>
                  {(provider) => (
                    <button
                      type="button"
                      onClick={() => handleExternalProviderLogin(provider.id)}
                      class="w-full inline-flex justify-center items-center px-4 py-2 border border-gray-300 rounded-lg shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    >
                      <Show when={provider.icon_url}>
                        <img
                          src={provider.icon_url}
                          alt={provider.display_name}
                          class="w-5 h-5 mr-2"
                        />
                      </Show>
                      <span>Continue with {provider.display_name}</span>
                    </button>
                  )}
                </For>
              </div>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
};

export default Login;
