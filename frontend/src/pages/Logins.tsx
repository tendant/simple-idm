import { Component, createSignal, onMount, Show } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { loginApi, type Login } from '../api/login';

const Logins: Component = () => {
  const navigate = useNavigate();
  const [logins, setLogins] = createSignal<Login[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  const fetchLogins = async () => {
    try {
      const data = await loginApi.listLogins();
      setLogins(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch logins');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this login?')) return;
    
    try {
      await loginApi.deleteLogin(id);
      setLogins(logins().filter(login => login.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete login');
    }
  };

  onMount(() => {
    fetchLogins();
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">User Logins</h1>
          <p class="mt-2 text-sm text-gray-9">
            A list of all user logins in the system including their username, email, and 2FA status.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            type="button"
            onClick={() => navigate('/logins/create')}
            class="inline-flex items-center justify-center rounded-lg border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 sm:w-auto"
          >
            Add Login
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

      <div class="mt-8 flex flex-col">
        <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
              <table class="min-w-full divide-y divide-gray-6">
                <thead>
                  <tr>
                    <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-11 sm:pl-6">
                      Username
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Email
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      2FA Enabled
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Password Last Changed
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
                  <Show when={!loading()} fallback={<tr><td colspan="6" class="text-center py-4">Loading...</td></tr>}>
                    {logins().length === 0 ? (
                      <tr>
                        <td colspan="6" class="text-center py-4 text-sm text-gray-9">No logins found</td>
                      </tr>
                    ) : (
                      logins().map((login) => (
                        <tr key={login.id}>
                          <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                            <a
                              href={`/logins/${login.id}/detail`}
                              onClick={(e) => {
                                e.preventDefault();
                                navigate(`/logins/${login.id}/detail`);
                              }}
                              class="text-blue-600 hover:text-blue-800 hover:underline"
                            >
                              {login.username}
                            </a>
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {login.email || '-'}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {login.two_factor_enabled ? (
                              <span class="inline-flex items-center rounded-md bg-green-50 px-2 py-1 text-xs font-medium text-green-700 ring-1 ring-inset ring-green-600/20">
                                Enabled
                              </span>
                            ) : (
                              <span class="inline-flex items-center rounded-md bg-gray-50 px-2 py-1 text-xs font-medium text-gray-600 ring-1 ring-inset ring-gray-500/10">
                                Disabled
                              </span>
                            )}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {login.password_last_changed ? new Date(login.password_last_changed).toLocaleDateString() : '-'}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {login.status || 'Active'}
                          </td>
                          <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                            <button
                              onClick={() => navigate(`/logins/${login.id}/edit`)}
                              class="text-blue-600 hover:text-blue-900 mr-4"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => handleDelete(login.id!)}
                              class="text-red-600 hover:text-red-900"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </Show>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Logins;
