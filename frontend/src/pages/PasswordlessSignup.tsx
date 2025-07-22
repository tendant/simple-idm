import { Component, createSignal } from 'solid-js';
import { useNavigate, A } from '@solidjs/router';
import { signupApi } from '../api/signup';

const PasswordlessSignup: Component = () => {
  const navigate = useNavigate();
  const [username, setUsername] = createSignal('');
  const [email, setEmail] = createSignal('');
  const [fullname, setFullname] = createSignal('');
  const [invitationCode, setInvitationCode] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const response = await signupApi.passwordlessSignup({
        ...(username() ? { username: username() } : {}),
        email: email(),
        ...(fullname() ? { fullname: fullname() } : {}),
        invitation_code: invitationCode() || undefined,
      });

      setSuccess('Account created successfully! You can now login with a magic link.');
      
      // Clear form
      setUsername('');
      setEmail('');
      setFullname('');
      setInvitationCode('');
      
      // Optionally redirect to magic link login page after a delay
      setTimeout(() => {
        navigate('/magic-link-login');
      }, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          Passwordless Signup
        </h2>
        <p class="mt-2 text-center text-sm text-gray-9">
          Create an account without a password
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
                for="email"
                class="block text-sm font-medium text-gray-11"
              >
                Email
              </label>
              <div class="mt-1">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autocomplete="email"
                  required
                  value={email()}
                  onInput={(e) => setEmail(e.currentTarget.value)}
                  class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                />
              </div>
            </div>

            <div>
              <label
                for="username"
                class="block text-sm font-medium text-gray-11"
              >
                Username (Optional)
              </label>
              <div class="mt-1">
                <input
                  id="username"
                  name="username"
                  type="text"
                  autocomplete="username"
                  value={username()}
                  onInput={(e) => setUsername(e.currentTarget.value)}
                  class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                />
              </div>
            </div>

            <div>
              <label
                for="fullname"
                class="block text-sm font-medium text-gray-11"
              >
                Full Name (Optional)
              </label>
              <div class="mt-1">
                <input
                  id="fullname"
                  name="fullname"
                  type="text"
                  autocomplete="name"
                  value={fullname()}
                  onInput={(e) => setFullname(e.currentTarget.value)}
                  class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                />
              </div>
            </div>

            <div>
              <label
                for="invitation-code"
                class="block text-sm font-medium text-gray-11"
              >
                Invitation Code (Optional)
              </label>
              <div class="mt-1">
                <input
                  id="invitation-code"
                  name="invitation-code"
                  type="text"
                  value={invitationCode()}
                  onInput={(e) => setInvitationCode(e.currentTarget.value)}
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
                {loading() ? 'Creating account...' : 'Create Account'}
              </button>
            </div>
            <div class="text-center">
              <div class="flex justify-center space-x-4">
                <A
                  href="/login"
                  class="text-sm text-blue-600 hover:text-blue-500"
                >
                  Already have an account? Sign in
                </A>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default PasswordlessSignup;
