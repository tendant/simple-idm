import { Component, createSignal, createEffect, Show, Index } from 'solid-js';
import { useParams, useNavigate } from '@solidjs/router';
import { oauth2ClientApi, OAuth2Client, OAuth2ClientUpdateRequest } from '../api/oauth2Clients';
import { Input } from '@/components/ui/input';

const EditOAuth2Client: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [client, setClient] = createSignal<OAuth2Client | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [redirectUris, setRedirectUris] = createSignal<string[]>([]);

  // Form fields
  const [clientName, setClientName] = createSignal('');
  const [clientType, setClientType] = createSignal<'confidential' | 'public'>('confidential');
  const [responseTypes, setResponseTypes] = createSignal<string[]>(['code']);
  const [grantTypes, setGrantTypes] = createSignal<string[]>(['authorization_code']);
  const [scope, setScope] = createSignal('');

  const availableGrantTypes = ['authorization_code'];
  const availableResponseTypes = ['code'];

  createEffect(async () => {
    try {
      setLoading(true);
      const clientData = await oauth2ClientApi.getClient(params.id);
      setClient(clientData);
      
      // Populate form fields
      setClientName(clientData.client_name);
      setClientType(clientData.client_type);
      setRedirectUris(clientData.redirect_uris || []);
      setResponseTypes(clientData.response_types || ['code']);
      setGrantTypes(clientData.grant_types || ['authorization_code']);
      setScope(clientData.scope || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load client');
    } finally {
      setLoading(false);
    }
  });

  const addRedirectUri = () => {
    setRedirectUris([...redirectUris(), '']);
  };

  const updateRedirectUri = (index: number, value: string) => {
    const uris = [...redirectUris()];
    uris[index] = value;
    setRedirectUris(uris);
  };

  const removeRedirectUri = (index: number) => {
    setRedirectUris(redirectUris().filter((_, i) => i !== index));
  };

  const handleResponseTypeChange = (type: string, checked: boolean) => {
    if (checked) {
      setResponseTypes([...responseTypes(), type]);
    } else {
      setResponseTypes(responseTypes().filter(t => t !== type));
    }
  };

  const handleGrantTypeChange = (type: string, checked: boolean) => {
    if (checked) {
      setGrantTypes([...grantTypes(), type]);
    } else {
      setGrantTypes(grantTypes().filter(t => t !== type));
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const filteredRedirectUris = redirectUris().filter(uri => uri.trim() !== '');

      if (!clientName().trim()) {
        throw new Error('Client name is required');
      }

      if (filteredRedirectUris.length === 0) {
        throw new Error('At least one redirect URI is required');
      }

      if (grantTypes().length === 0) {
        throw new Error('At least one grant type must be selected');
      }

      if (responseTypes().length === 0) {
        throw new Error('At least one response type must be selected');
      }

      const updateData: OAuth2ClientUpdateRequest = {
        client_name: clientName().trim(),
        redirect_uris: filteredRedirectUris,
        client_type: clientType(),
        response_types: responseTypes(),
        grant_types: grantTypes(),
      };

      // Add optional fields if they have values
      if (scope().trim()) updateData.scope = scope().trim();

      await oauth2ClientApi.updateClient(params.id, updateData);
      navigate(`/oauth2-clients/${params.id}/detail`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update client');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div class="max-w-4xl mx-auto">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-gray-900">Edit OAuth2 Client</h1>
        <p class="mt-2 text-gray-600">Update OAuth2 client configuration</p>
      </div>

      <Show when={loading()}>
        <div class="flex justify-center py-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      </Show>

      <Show when={!loading() && client()}>
        <div class="bg-white shadow-sm rounded-lg">
          <form onSubmit={handleSubmit} class="p-6 space-y-6">
            <Show when={error()}>
              <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
                {error()}
              </div>
            </Show>

            {/* Basic Information */}
            <div class="border-b border-gray-6 pb-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12">Basic Information</h3>
              <p class="mt-1 text-sm text-gray-9">
                Basic details about your OAuth2 client application.
              </p>

              <div class="mt-4 grid grid-cols-1 gap-6 sm:grid-cols-2">
                <div>
                  <label class="block text-sm font-medium text-gray-700">Client ID</label>
                  <input
                    type="text"
                    value={client()?.client_id || ''}
                    readonly
                    class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 bg-gray-50 text-gray-500 cursor-not-allowed"
                  />
                  <p class="mt-1 text-sm text-gray-8">The client ID cannot be changed after creation.</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700">Client Name *</label>
                  <input
                    type="text"
                    value={clientName()}
                    onInput={(e) => setClientName(e.currentTarget.value)}
                    required
                    class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700">Client Type</label>
                  <select
                    value={clientType()}
                    onChange={(e) => setClientType(e.currentTarget.value as 'confidential' | 'public')}
                    class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="confidential">Confidential</option>
                    <option value="public">Public</option>
                  </select>
                </div>
              </div>
            </div>

            {/* OAuth2 Configuration */}
            <div class="border-b border-gray-6 pb-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12">OAuth2 Configuration</h3>
              <p class="mt-1 text-sm text-gray-9">
                Configure the OAuth2 flow settings for your client.
              </p>

              <div class="mt-4 space-y-6">
                {/* Redirect URIs */}
                <div>
                  <label class="block text-sm font-medium text-gray-11">
                    Redirect URIs <span class="text-red-500">*</span>
                  </label>
                  <p class="mt-1 text-sm text-gray-8">
                    Valid redirect URIs for your application. HTTPS is required except for localhost.
                  </p>
                  <div class="mt-2 space-y-2">
                    <Index each={redirectUris()}>
                      {(uri, i) => (
                        <div class="flex items-center space-x-2">
                          <Input
                            type="url"
                            value={uri()}
                            onInput={(e) => updateRedirectUri(i, e.currentTarget.value)}
                            placeholder="https://example.com/callback"
                            class="flex-1"
                          />
                          <button
                            type="button"
                            onClick={() => removeRedirectUri(i)}
                            class="px-3 py-2 text-red-600 hover:text-red-800"
                          >
                            Remove
                          </button>
                        </div>
                      )}
                    </Index>
                    <button
                      type="button"
                      onClick={addRedirectUri}
                      class="inline-flex items-center rounded-lg bg-gray-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-gray-500"
                    >
                      Add Redirect URI
                    </button>
                  </div>
                </div>

                {/* Response Types */}
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">Response Types</label>
                  <div class="space-y-2">
                    {availableResponseTypes.map((type) => (
                      <label class="flex items-center">
                        <input
                          type="checkbox"
                          checked={responseTypes().includes(type)}
                          onChange={(e) => handleResponseTypeChange(type, e.currentTarget.checked)}
                          class="mr-2"
                        />
                        {type}
                      </label>
                    ))}
                  </div>
                </div>

                {/* Grant Types */}
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">Grant Types</label>
                  <div class="space-y-2">
                    {availableGrantTypes.map((type) => (
                      <label class="flex items-center">
                        <input
                          type="checkbox"
                          checked={grantTypes().includes(type)}
                          onChange={(e) => handleGrantTypeChange(type, e.currentTarget.checked)}
                          class="mr-2"
                        />
                        {type}
                      </label>
                    ))}
                  </div>
                </div>

                {/* Scope */}
                <div>
                  <label class="block text-sm font-medium text-gray-700">Scope</label>
                  <input
                    type="text"
                    value={scope()}
                    onInput={(e) => setScope(e.currentTarget.value)}
                    placeholder="openid profile email"
                    class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p class="mt-1 text-sm text-gray-8">
                    Space-separated list of scopes that your client will request.
                  </p>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div class="flex justify-end space-x-3 pt-6 border-t">
              <button
                type="button"
                onClick={() => navigate(`/oauth2-clients/${params.id}/detail`)}
                class="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving()}
                class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {saving() ? 'Updating...' : 'Update Client'}
              </button>
            </div>
          </form>
        </div>
      </Show>
    </div>
  );
};

export default EditOAuth2Client;
