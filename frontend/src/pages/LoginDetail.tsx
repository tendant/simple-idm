import { Component, createSignal, onMount, Show, For } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import { loginApi, type Login, type TwoFactorMethod } from '../api/login';
import { userApi, type User } from '../api/user';
import { twoFactorApi } from '../api/twoFactor';

const LoginDetail: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [login, setLogin] = createSignal<Login | null>(null);
  const [associatedUsers, setAssociatedUsers] = createSignal<User[]>([]);
  const [twoFactorMethods, setTwoFactorMethods] = createSignal<TwoFactorMethod[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [loadingUsers, setLoadingUsers] = createSignal(true);
  const [loadingTwoFactorMethods, setLoadingTwoFactorMethods] = createSignal(true);
  const [processingMethod, setProcessingMethod] = createSignal<string | null>(null);

  onMount(() => {
    fetchLogin();
    fetchAssociatedUsers();
    fetchTwoFactorMethods();
  });

  const fetchLogin = async () => {
    try {
      const data = await loginApi.getLogin(params.id);
      setLogin(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch login details');
    } finally {
      setLoading(false);
    }
  };

  const fetchAssociatedUsers = async () => {
    try {
      const users = await userApi.listUsers();
      // Filter users whose login_id matches the current login's ID
      setAssociatedUsers(users.filter(user => user.login_id === params.id));
    } catch (err) {
      console.error('Failed to fetch associated users:', err);
    } finally {
      setLoadingUsers(false);
    }
  };
  
  const fetchTwoFactorMethods = async () => {
    try {
      const methods = await loginApi.get2FAMethods(params.id);
      setTwoFactorMethods(methods);
    } catch (err) {
      console.error('Failed to fetch 2FA methods:', err);
    } finally {
      setLoadingTwoFactorMethods(false);
    }
  };

  const toggleTwoFactorMethod = async (methodType: string, currentStatus: boolean) => {
    setProcessingMethod(methodType);
    try {
      if (currentStatus) {
        // Disable the method
        await twoFactorApi.disable2FAMethod(params.id, methodType);
      } else {
        // Enable the method
        await twoFactorApi.enable2FAMethod(params.id, methodType);
      }
      // Refresh the 2FA methods list
      await fetchTwoFactorMethods();
    } catch (err) {
      console.error(`Failed to ${currentStatus ? 'disable' : 'enable'} 2FA method:`, err);
      setError(err instanceof Error ? err.message : `Failed to ${currentStatus ? 'disable' : 'enable'} 2FA method`);
    } finally {
      setProcessingMethod(null);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-11">Login Details</h1>
          <p class="mt-2 text-sm text-gray-9">
            View detailed information about this login.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            type="button"
            onClick={() => navigate(`/logins/${params.id}/edit`)}
            class="inline-flex items-center justify-center rounded-lg border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 sm:w-auto"
          >
            Edit Login
          </button>
        </div>
      </div>

      <Show when={error()}>
        <div class="mt-4 bg-red-50 p-4 rounded-lg">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-red-800">{error()}</h3>
            </div>
          </div>
        </div>
      </Show>

      <Show when={loading()}>
        <div class="mt-8 text-center">
          <p>Loading login details...</p>
        </div>
      </Show>

      <Show when={!loading() && login()}>
        <div class="mt-8 overflow-hidden bg-white shadow sm:rounded-lg">
          <div class="px-4 py-5 sm:px-6">
            <h3 class="text-lg font-medium leading-6 text-gray-900">Login Information</h3>
            <p class="mt-1 max-w-2xl text-sm text-gray-500">Details and account settings.</p>
          </div>
          <div class="border-t border-gray-200">
            <dl>
              <div class="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Username</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">{login()?.username}</dd>
              </div>
              <div class="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Status</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <span class={`inline-flex items-center rounded-md px-2.5 py-0.5 text-sm font-medium ${login()?.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                    {login()?.status || 'Unknown'}
                  </span>
                </dd>
              </div>
              <div class="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Two-Factor Authentication</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  {login()?.two_factor_enabled ? 'Enabled' : 'Disabled'}
                </dd>
              </div>
              <div class="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Created At</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">{formatDate(login()?.created_at)}</dd>
              </div>
              <div class="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Last Modified</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">{formatDate(login()?.last_modified_at)}</dd>
              </div>
              <div class="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-gray-500">Password Last Changed</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">{formatDate(login()?.password_last_changed)}</dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Two-Factor Authentication Methods Section */}
        <div class="mt-8">
          <h2 class="text-xl font-semibold text-gray-11">Two-Factor Authentication Methods</h2>
          <p class="mt-2 text-sm text-gray-9">
            Available 2FA methods for this login account.
          </p>

          <Show when={loadingTwoFactorMethods()}>
            <div class="mt-4 text-center">
              <p>Loading 2FA methods...</p>
            </div>
          </Show>

          <Show when={!loadingTwoFactorMethods() && twoFactorMethods().length === 0}>
            <div class="mt-4 bg-yellow-50 p-4 rounded-lg">
              <div class="flex">
                <div class="flex-shrink-0">
                  <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                  </svg>
                </div>
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-yellow-800">No 2FA methods configured for this login</h3>
                </div>
              </div>
            </div>
          </Show>

          <Show when={!loadingTwoFactorMethods() && twoFactorMethods().length > 0}>
            <div class="mt-4 overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
              <table class="min-w-full divide-y divide-gray-6">
                <thead>
                  <tr>
                    <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-11 sm:pl-6">
                      Method Type
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Status
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-6">
                  <For each={twoFactorMethods()}>
                    {(method) => (
                      <tr>
                        <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                          {method.type === 'email' ? 'Email' : 
                           method.type === 'totp' ? 'Authenticator App (TOTP)' : 
                           method.type === 'sms' ? 'SMS' : method.type}
                        </td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                          <span class={`inline-flex items-center rounded-md px-2.5 py-0.5 text-sm font-medium ${method.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                            {method.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </td>
                        <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                          <div class="flex justify-end">
                            <button
                              onClick={() => toggleTwoFactorMethod(method.type, method.enabled)}
                              disabled={processingMethod() === method.type}
                              class={`px-3 py-1 rounded-md text-sm font-medium ${method.enabled 
                                ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                                : 'bg-green-100 text-green-700 hover:bg-green-200'} 
                                ${processingMethod() === method.type ? 'opacity-50 cursor-not-allowed' : ''}`}
                            >
                              {processingMethod() === method.type 
                                ? 'Processing...' 
                                : method.enabled ? 'Disable' : 'Enable'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>

        {/* Associated Users Section */}
        <div class="mt-8">
          <h2 class="text-xl font-semibold text-gray-11">Associated Users</h2>
          <p class="mt-2 text-sm text-gray-9">
            Users that are associated with this login account.
          </p>

          <Show when={loadingUsers()}>
            <div class="mt-4 text-center">
              <p>Loading associated users...</p>
            </div>
          </Show>

          <Show when={!loadingUsers() && associatedUsers().length === 0}>
            <div class="mt-4 bg-yellow-50 p-4 rounded-lg">
              <div class="flex">
                <div class="flex-shrink-0">
                  <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                  </svg>
                </div>
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-yellow-800">No users are associated with this login</h3>
                </div>
              </div>
            </div>
          </Show>

          <Show when={!loadingUsers() && associatedUsers().length > 0}>
            <div class="mt-4 overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
              <table class="min-w-full divide-y divide-gray-6">
                <thead>
                  <tr>
                    <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-11 sm:pl-6">
                      Name
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Email
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Roles
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-6">
                  <For each={associatedUsers()}>
                    {(user) => (
                      <tr>
                        <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                          {user.name || '-'}
                        </td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                          {user.email}
                        </td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                          <div class="flex flex-wrap gap-1">
                            {user.roles?.map((role: { id?: string; name?: string }) => (
                              <span
                                class="inline-flex items-center rounded-md bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-600/20"
                              >
                                {role.name}
                              </span>
                            )) || '-'}
                          </div>
                        </td>
                        <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                          <button
                            onClick={() => navigate(`/users/${user.id}/edit`)}
                            class="text-indigo-600 hover:text-indigo-900"
                          >
                            Edit<span class="sr-only">, {user.name}</span>
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
};

export default LoginDetail;
