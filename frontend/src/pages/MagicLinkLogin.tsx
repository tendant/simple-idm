import { Component, createSignal } from 'solid-js';
import { A } from '@solidjs/router';
import { loginApi } from '../api/login';

const MagicLinkLogin: Component = () => {
  const [username, setUsername] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const response = await loginApi.requestMagicLink(username());
      setSuccess('Magic link sent! Please check your email to complete the login process.');
      
      // Clear form
      setUsername('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request magic link');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          Magic Link Login
        </h2>
        <p class="mt-2 text-center text-sm text-gray-9">
          Enter your username to receive a login link via email
        </p>
      </div>

      <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow-lg rounded-lg sm:px-10">
          {success() && (
            <div class="rounded-lg bg-green-2 p-4 mb-6">
              <div class="flex">
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-green-11">{success()}</h3>
                </div>
              </div>
            </div>
          )}

          {error() && (
            <div class="rounded-lg bg-red-2 p-4 mb-6">
              <div class="flex">
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-red-11">{error()}</h3>
                </div>
              </div>
            </div>
          )}

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
              <button
                type="submit"
                disabled={loading()}
                class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading() ? 'Sending...' : 'Send Magic Link'}
              </button>
            </div>
            <div class="text-center">
              <div class="flex justify-center space-x-4">
                <A
                  href="/login"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Sign in with password
                </A>
                <span class="text-gray-8">•</span>
                <A
                  href="/passwordless-signup"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Create an account
                </A>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default MagicLinkLogin;
