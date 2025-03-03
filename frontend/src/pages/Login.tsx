import { Component, createSignal } from 'solid-js';
import { useNavigate, useSearchParams, A } from '@solidjs/router';
import { userApi } from '../api/user';
import { DeliveryOption } from '../api/twoFactor';

const Login: Component = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await userApi.login({
        username: username(),
        password: password(),
      });

      // Check if 2FA is required
      if (response.status === '2fa_required') {
        // Redirect to 2FA verification page with necessary params
        const params = new URLSearchParams();
        params.set('token', response.temp_token);
        
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
          params.set('redirect', searchParams.redirect);
        }
        navigate(`/two-factor-verification?${params.toString()}`);
        return;
      }

      // Regular login flow (no 2FA)
      // Store the user info in localStorage
      localStorage.setItem('user', JSON.stringify(response));

      // Redirect to the original page or default to /users
      const redirectPath = searchParams.redirect || '/users';
      navigate(redirectPath);
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
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
