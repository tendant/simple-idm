import { useNavigate } from '@solidjs/router';
import { Component, createSignal, onMount, For, Show } from 'solid-js';
import { oauth2ClientApi, type OAuth2Client } from '../api/oauth2Clients';
import { formatDate, truncateString } from '../api/utils';

const OAuth2Clients: Component = () => {
  const navigate = useNavigate();
  const [clients, setClients] = createSignal<OAuth2Client[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [deleting, setDeleting] = createSignal<string | null>(null);

  const fetchClients = async () => {
    try {
      setLoading(true);
      const response = await oauth2ClientApi.listClients();
      setClients(response.clients || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch OAuth2 clients');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (clientId: string, clientName: string) => {
    if (!confirm(`Are you sure you want to delete the OAuth2 client "${clientName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      setDeleting(clientId);
      await oauth2ClientApi.deleteClient(clientId);
      await fetchClients(); // Refresh the list
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete OAuth2 client');
    } finally {
      setDeleting(null);
    }
  };

  const getClientTypeColor = (type: string) => {
    return type === 'confidential' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800';
  };

  const getStatusColor = (isActive: boolean) => {
    return isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800';
  };

  onMount(() => {
    fetchClients();
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-12 sm:truncate sm:text-3xl sm:tracking-tight">
            OAuth2 Clients
          </h2>
          <p class="mt-1 text-sm text-gray-9">
            Manage OAuth2 clients for your identity provider. These clients can authenticate users and access protected resources.
          </p>
        </div>
        <div class="mt-4 flex md:ml-4 md:mt-0">
          <button
            type="button"
            onClick={() => navigate('/oauth2-clients/create')}
            class="inline-flex items-center rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            Register New Client
          </button>
        </div>
      </div>

      <Show when={error()}>
        <div class="mt-6 rounded-lg bg-red-50 p-4">
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

      <Show when={!loading()} fallback={<div class="mt-6 text-center">Loading OAuth2 clients...</div>}>
        <div class="mt-8 flow-root">
          <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
            <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
              <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
                <table class="min-w-full divide-y divide-gray-6">
                  <thead class="bg-gray-3">
                    <tr>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Client
                      </th>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Type
                      </th>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Status
                      </th>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Grant Types
                      </th>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Created
                      </th>
                      <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-11 uppercase tracking-wider">
                        Last Used
                      </th>
                      <th scope="col" class="relative px-6 py-3">
                        <span class="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody class="bg-white divide-y divide-gray-6">
                    <Show when={clients().length === 0}>
                      <tr>
                        <td colspan="7" class="px-6 py-4 text-center text-sm text-gray-9">
                          No OAuth2 clients found. 
                          <button
                            type="button"
                            onClick={() => navigate('/oauth2-clients/create')}
                            class="ml-1 text-blue-600 hover:text-blue-500"
                          >
                            Register your first client
                          </button>
                        </td>
                      </tr>
                    </Show>
                    <For each={clients()}>
                      {(client) => (
                        <tr class="hover:bg-gray-2">
                          <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                              <div>
                                <div class="text-sm font-medium text-gray-12">
                                  {client.client_name}
                                </div>
                                <div class="text-sm text-gray-9 font-mono">
                                  {truncateString(client.client_id, 20)}
                                </div>
                                <Show when={client.description}>
                                  <div class="text-xs text-gray-8 mt-1">
                                    {truncateString(client.description!, 50)}
                                  </div>
                                </Show>
                              </div>
                            </div>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <span class={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getClientTypeColor(client.client_type)}`}>
                              {client.client_type}
                            </span>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <span class={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(client.is_active)}`}>
                              {client.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-9">
                            <div class="flex flex-wrap gap-1">
                              <For each={client.grant_types.slice(0, 2)}>
                                {(grantType) => (
                                  <span class="inline-flex px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 rounded">
                                    {grantType}
                                  </span>
                                )}
                              </For>
                              <Show when={client.grant_types.length > 2}>
                                <span class="inline-flex px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 rounded">
                                  +{client.grant_types.length - 2} more
                                </span>
                              </Show>
                            </div>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-9">
                            {formatDate(client.created_at)}
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-9">
                            {client.last_used_at ? formatDate(client.last_used_at) : 'Never'}
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <div class="flex justify-end space-x-2">
                              <button
                                type="button"
                                onClick={() => navigate(`/oauth2-clients/${client.client_id}/detail`)}
                                class="text-blue-600 hover:text-blue-900"
                              >
                                View
                              </button>
                              <button
                                type="button"
                                onClick={() => navigate(`/oauth2-clients/${client.client_id}/edit`)}
                                class="text-indigo-600 hover:text-indigo-900"
                              >
                                Edit
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDelete(client.client_id, client.client_name)}
                                disabled={deleting() === client.client_id}
                                class="text-red-600 hover:text-red-900 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                {deleting() === client.client_id ? 'Deleting...' : 'Delete'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default OAuth2Clients;
