import { useNavigate, useParams } from '@solidjs/router';
import { Component, createSignal, onMount, For, Show } from 'solid-js';
import { oauth2ClientApi, type OAuth2Client } from '../api/oauth2Clients';
import { formatDate } from '../api/utils';

const OAuth2ClientDetail: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [client, setClient] = createSignal<OAuth2Client | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [regeneratingSecret, setRegeneratingSecret] = createSignal(false);
  const [newSecret, setNewSecret] = createSignal<string | null>(null);

  const fetchClient = async () => {
    try {
      setLoading(true);
      const data = await oauth2ClientApi.getClient(params.id);
      setClient(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch OAuth2 client');
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerateSecret = async () => {
    if (!confirm('Are you sure you want to regenerate the client secret? The current secret will be invalidated immediately.')) {
      return;
    }

    try {
      setRegeneratingSecret(true);
      setError(null);
      const result = await oauth2ClientApi.regenerateClientSecret(params.id);
      setNewSecret(result.client_secret);
      // Update the client's updated_at timestamp
      if (client()) {
        setClient({ ...client()!, updated_at: result.updated_at });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to regenerate client secret');
    } finally {
      setRegeneratingSecret(false);
    }
  };

  const getClientTypeColor = (type: string) => {
    return type === 'confidential' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800';
  };

  const getStatusColor = (isActive: boolean) => {
    return isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800';
  };

  onMount(() => {
    fetchClient();
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-12 sm:truncate sm:text-3xl sm:tracking-tight">
            OAuth2 Client Details
          </h2>
        </div>
        <div class="mt-4 flex space-x-3 md:ml-4 md:mt-0">
          <button
            type="button"
            onClick={() => navigate('/oauth2-clients')}
            class="inline-flex items-center rounded-lg bg-white px-3 py-2 text-sm font-semibold text-gray-11 shadow-sm ring-1 ring-inset ring-gray-6 hover:bg-gray-3"
          >
            Back to Clients
          </button>
          <Show when={client()}>
            <button
              type="button"
              onClick={() => navigate(`/oauth2-clients/${params.id}/edit`)}
              class="inline-flex items-center rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
            >
              Edit Client
            </button>
          </Show>
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

      <Show when={newSecret()}>
        <div class="mt-6 overflow-hidden bg-white shadow rounded-lg">
          <div class="px-4 py-5 sm:p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg class="h-8 w-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div class="ml-3">
                <h3 class="text-lg font-medium text-gray-12">New Client Secret Generated</h3>
                <div class="mt-2 text-sm text-gray-9">
                  <p>A new client secret has been generated. Please save it securely:</p>
                </div>
              </div>
            </div>
            
            <div class="mt-6">
              <label class="block text-sm font-medium text-gray-11">New Client Secret</label>
              <div class="mt-1 flex rounded-lg shadow-sm">
                <input
                  type="text"
                  readonly
                  value={newSecret()!}
                  class="block w-full rounded-lg border-gray-6 bg-gray-2 px-3 py-2 text-sm font-mono"
                />
                <button
                  type="button"
                  onClick={() => navigator.clipboard.writeText(newSecret()!)}
                  class="ml-2 inline-flex items-center rounded-lg bg-gray-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-gray-500"
                >
                  Copy
                </button>
              </div>
              <p class="mt-1 text-sm text-red-600">
                ⚠️ This client secret will not be shown again. Please save it securely.
              </p>
            </div>

            <div class="mt-6 flex justify-end">
              <button
                type="button"
                onClick={() => setNewSecret(null)}
                class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                Continue
              </button>
            </div>
          </div>
        </div>
      </Show>

      <Show when={!loading() && client()} fallback={<div class="mt-6 text-center">Loading OAuth2 client...</div>}>
        <div class="mt-8 space-y-6">
          {/* Basic Information */}
          <div class="overflow-hidden bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12 mb-4">Basic Information</h3>
              
              <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                <div>
                  <dt class="text-sm font-medium text-gray-11">Client Name</dt>
                  <dd class="mt-1 text-sm text-gray-12">{client()!.client_name}</dd>
                </div>
                
                <div>
                  <dt class="text-sm font-medium text-gray-11">Client ID</dt>
                  <dd class="mt-1 text-sm text-gray-12 font-mono break-all">{client()!.client_id}</dd>
                </div>
                
                <div>
                  <dt class="text-sm font-medium text-gray-11">Client Type</dt>
                  <dd class="mt-1">
                    <span class={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getClientTypeColor(client()!.client_type)}`}>
                      {client()!.client_type}
                    </span>
                  </dd>
                </div>
                
                <div>
                  <dt class="text-sm font-medium text-gray-11">Status</dt>
                  <dd class="mt-1">
                    <span class={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(client()!.is_active)}`}>
                      {client()!.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </dd>
                </div>
                
                <Show when={client()!.description}>
                  <div class="sm:col-span-2">
                    <dt class="text-sm font-medium text-gray-11">Description</dt>
                    <dd class="mt-1 text-sm text-gray-12">{client()!.description}</dd>
                  </div>
                </Show>
                
                <div>
                  <dt class="text-sm font-medium text-gray-11">Created</dt>
                  <dd class="mt-1 text-sm text-gray-12">{formatDate(client()!.created_at)}</dd>
                </div>
                
                <div>
                  <dt class="text-sm font-medium text-gray-11">Last Modified</dt>
                  <dd class="mt-1 text-sm text-gray-12">{formatDate(client()!.updated_at)}</dd>
                </div>
                
                <Show when={client()!.last_used_at}>
                  <div>
                    <dt class="text-sm font-medium text-gray-11">Last Used</dt>
                    <dd class="mt-1 text-sm text-gray-12">{formatDate(client()!.last_used_at!)}</dd>
                  </div>
                </Show>
              </dl>
            </div>
          </div>

          {/* OAuth2 Configuration */}
          <div class="overflow-hidden bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12 mb-4">OAuth2 Configuration</h3>
              
              <dl class="space-y-6">
                <div>
                  <dt class="text-sm font-medium text-gray-11">Redirect URIs</dt>
                  <dd class="mt-1">
                    <ul class="space-y-1">
                      <For each={client()!.redirect_uris}>
                        {(uri) => (
                          <li class="text-sm text-gray-12 font-mono bg-gray-2 px-2 py-1 rounded break-all">
                            {uri}
                          </li>
                        )}
                      </For>
                    </ul>
                  </dd>
                </div>
                
                <div class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                  <div>
                    <dt class="text-sm font-medium text-gray-11">Grant Types</dt>
                    <dd class="mt-1">
                      <div class="flex flex-wrap gap-1">
                        <For each={client()!.grant_types}>
                          {(grantType) => (
                            <span class="inline-flex px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded">
                              {grantType}
                            </span>
                          )}
                        </For>
                      </div>
                    </dd>
                  </div>
                  
                  <div>
                    <dt class="text-sm font-medium text-gray-11">Response Types</dt>
                    <dd class="mt-1">
                      <div class="flex flex-wrap gap-1">
                        <For each={client()!.response_types}>
                          {(responseType) => (
                            <span class="inline-flex px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">
                              {responseType}
                            </span>
                          )}
                        </For>
                      </div>
                    </dd>
                  </div>
                </div>
                
                <Show when={client()!.scope}>
                  <div>
                    <dt class="text-sm font-medium text-gray-11">Scope</dt>
                    <dd class="mt-1 text-sm text-gray-12 font-mono bg-gray-2 px-2 py-1 rounded">
                      {client()!.scope}
                    </dd>
                  </div>
                </Show>
                
                <Show when={client()!.token_endpoint_auth_method}>
                  <div>
                    <dt class="text-sm font-medium text-gray-11">Token Endpoint Auth Method</dt>
                    <dd class="mt-1 text-sm text-gray-12">{client()!.token_endpoint_auth_method}</dd>
                  </div>
                </Show>
              </dl>
            </div>
          </div>

          {/* Client Secret Management */}
          <Show when={client()!.client_type === 'confidential'}>
            <div class="overflow-hidden bg-white shadow rounded-lg">
              <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg font-medium leading-6 text-gray-12">Client Secret Management</h3>
                <div class="mt-2 max-w-xl text-sm text-gray-9">
                  <p>
                    Confidential clients use a client secret for authentication. You can regenerate the secret if needed.
                  </p>
                </div>
                <div class="mt-5">
                  <button
                    type="button"
                    onClick={handleRegenerateSecret}
                    disabled={regeneratingSecret()}
                    class="inline-flex items-center rounded-lg bg-red-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {regeneratingSecret() ? 'Regenerating...' : 'Regenerate Client Secret'}
                  </button>
                </div>
              </div>
            </div>
          </Show>

          {/* Optional Metadata */}
          <Show when={client()!.client_uri || client()!.logo_uri || client()!.tos_uri || client()!.policy_uri || client()!.jwks_uri || (client()!.contacts && client()!.contacts.length > 0)}>
            <div class="overflow-hidden bg-white shadow rounded-lg">
              <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg font-medium leading-6 text-gray-12 mb-4">Additional Information</h3>
                
                <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                  <Show when={client()!.client_uri}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Client URI</dt>
                      <dd class="mt-1 text-sm text-blue-600 hover:text-blue-500">
                        <a href={client()!.client_uri} target="_blank" rel="noopener noreferrer" class="break-all">
                          {client()!.client_uri}
                        </a>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()!.logo_uri}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Logo URI</dt>
                      <dd class="mt-1 text-sm text-blue-600 hover:text-blue-500">
                        <a href={client()!.logo_uri} target="_blank" rel="noopener noreferrer" class="break-all">
                          {client()!.logo_uri}
                        </a>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()!.tos_uri}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Terms of Service URI</dt>
                      <dd class="mt-1 text-sm text-blue-600 hover:text-blue-500">
                        <a href={client()!.tos_uri} target="_blank" rel="noopener noreferrer" class="break-all">
                          {client()!.tos_uri}
                        </a>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()!.policy_uri}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Privacy Policy URI</dt>
                      <dd class="mt-1 text-sm text-blue-600 hover:text-blue-500">
                        <a href={client()!.policy_uri} target="_blank" rel="noopener noreferrer" class="break-all">
                          {client()!.policy_uri}
                        </a>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()!.jwks_uri}>
                    <div class="sm:col-span-2">
                      <dt class="text-sm font-medium text-gray-11">JWKS URI</dt>
                      <dd class="mt-1 text-sm text-blue-600 hover:text-blue-500">
                        <a href={client()!.jwks_uri} target="_blank" rel="noopener noreferrer" class="break-all">
                          {client()!.jwks_uri}
                        </a>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()!.contacts && client()!.contacts.length > 0}>
                    <div class="sm:col-span-2">
                      <dt class="text-sm font-medium text-gray-11">Contact Emails</dt>
                      <dd class="mt-1">
                        <ul class="space-y-1">
                          <For each={client()!.contacts}>
                            {(contact) => (
                              <li class="text-sm text-blue-600 hover:text-blue-500">
                                <a href={`mailto:${contact}`}>{contact}</a>
                              </li>
                            )}
                          </For>
                        </ul>
                      </dd>
                    </div>
                  </Show>
                  
                  <Show when={client()?.software_id}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Software ID</dt>
                      <dd class="mt-1 text-sm text-gray-12">{client()?.software_id}</dd>
                    </div>
                  </Show>
                  
                  <Show when={client()?.software_version}>
                    <div>
                      <dt class="text-sm font-medium text-gray-11">Software Version</dt>
                      <dd class="mt-1 text-sm text-gray-12">{client()?.software_version}</dd>
                    </div>
                  </Show>
                </dl>
              </div>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
};

export default OAuth2ClientDetail;
