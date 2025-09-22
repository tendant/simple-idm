import { useNavigate } from '@solidjs/router';
import { Component, createSignal, For, Index, Show } from 'solid-js';
import { oauth2ClientApi, type OAuth2ClientRegistrationRequest } from '../api/oauth2Clients';
import { Input } from '@/components/ui/input';

const CreateOAuth2Client: Component = () => {
  const navigate = useNavigate();
  const [clientId, setClientId] = createSignal('');
  const [clientName, setClientName] = createSignal('');
  const [clientType, setClientType] = createSignal<'confidential' | 'public'>('confidential');
  const [redirectUris, setRedirectUris] = createSignal<string[]>(['']);
  const [grantTypes, setGrantTypes] = createSignal<string[]>(['authorization_code']);
  const [responseTypes, setResponseTypes] = createSignal<string[]>(['code']);
  const [scope, setScope] = createSignal('');
  
  const [error, setError] = createSignal<string | null>(null);
  const [saving, setSaving] = createSignal(false);
  const [registrationResult, setRegistrationResult] = createSignal<{client_id: string, client_secret?: string} | null>(null);

  const availableGrantTypes = ['authorization_code'];
  const availableResponseTypes = ['code'];

  const addRedirectUri = () => {
    setRedirectUris([...redirectUris(), '']);
  };

  const removeRedirectUri = (index: number) => {
    const uris = redirectUris().filter((_, i) => i !== index);
    setRedirectUris(uris.length > 0 ? uris : ['']);
  };

  const updateRedirectUri = (index: number, value: string) => {
    const uris = [...redirectUris()];
    uris[index] = value;
    setRedirectUris(uris);
  };

  const toggleGrantType = (grantType: string) => {
    const current = grantTypes();
    if (current.includes(grantType)) {
      setGrantTypes(current.filter(gt => gt !== grantType));
    } else {
      setGrantTypes([...current, grantType]);
    }
  };

  const toggleResponseType = (responseType: string) => {
    const current = responseTypes();
    if (current.includes(responseType)) {
      setResponseTypes(current.filter(rt => rt !== responseType));
    } else {
      setResponseTypes([...current, responseType]);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    
    setSaving(true);
    setError(null);

    try {
      // Filter out empty values
      const filteredRedirectUris = redirectUris().filter(uri => uri.trim() !== '');

      if (!clientId().trim()) {
        throw new Error('Client ID is required');
      }

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

      const registrationData: OAuth2ClientRegistrationRequest = {
        client_id: clientId().trim(),
        client_name: clientName().trim(),
        redirect_uris: filteredRedirectUris,
        client_type: clientType(),
        grant_types: grantTypes(),
        response_types: responseTypes(),
      };

      // Add optional fields if they have values
      if (scope().trim()) registrationData.scope = scope().trim();

      const result = await oauth2ClientApi.registerClient(registrationData);
      setRegistrationResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register OAuth2 client');
      setSaving(false);
    }
  };

  const handleContinue = () => {
    navigate('/oauth2-clients');
  };

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-12 sm:truncate sm:text-3xl sm:tracking-tight">
            Register New OAuth2 Client
          </h2>
          <p class="mt-1 text-sm text-gray-9">
            Register a new OAuth2 client that can authenticate users and access protected resources.
          </p>
        </div>
        <div class="mt-4 flex md:ml-4 md:mt-0">
          <button
            type="button"
            onClick={() => navigate('/oauth2-clients')}
            class="inline-flex items-center rounded-lg bg-white px-3 py-2 text-sm font-semibold text-gray-11 shadow-sm ring-1 ring-inset ring-gray-6 hover:bg-gray-3"
          >
            Cancel
          </button>
        </div>
      </div>

      <Show when={registrationResult()}>
        <div class="mt-8 overflow-hidden bg-white shadow rounded-lg">
          <div class="px-4 py-5 sm:p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg class="h-8 w-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div class="ml-3">
                <h3 class="text-lg font-medium text-gray-12">OAuth2 Client Registered Successfully!</h3>
                <div class="mt-2 text-sm text-gray-9">
                  <p>Your OAuth2 client has been registered. Please save the following credentials securely:</p>
                </div>
              </div>
            </div>
            
            <div class="mt-6 space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-11">Client ID</label>
                <div class="mt-1 flex rounded-lg shadow-sm">
                  <input
                    type="text"
                    readonly
                    value={registrationResult()!.client_id}
                    class="block w-full rounded-lg border-gray-6 bg-gray-2 px-3 py-2 text-sm font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => navigator.clipboard.writeText(registrationResult()!.client_id)}
                    class="ml-2 inline-flex items-center rounded-lg bg-gray-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-gray-500"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <Show when={registrationResult()!.client_secret}>
                <div>
                  <label class="block text-sm font-medium text-gray-11">Client Secret</label>
                  <div class="mt-1 flex rounded-lg shadow-sm">
                    <input
                      type="text"
                      readonly
                      value={registrationResult()!.client_secret}
                      class="block w-full rounded-lg border-gray-6 bg-gray-2 px-3 py-2 text-sm font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(registrationResult()!.client_secret!)}
                      class="ml-2 inline-flex items-center rounded-lg bg-gray-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-gray-500"
                    >
                      Copy
                    </button>
                  </div>
                  <p class="mt-1 text-sm text-red-600">
                    ⚠️ This client secret will not be shown again. Please save it securely.
                  </p>
                </div>
              </Show>
            </div>

            <div class="mt-6 flex justify-end">
              <button
                type="button"
                onClick={handleContinue}
                class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                Continue to OAuth2 Clients
              </button>
            </div>
          </div>
        </div>
      </Show>

      <Show when={!registrationResult()}>
        <div class="mt-8 flow-root">
          <div class="overflow-hidden bg-white shadow rounded-lg">
            <form onSubmit={handleSubmit} class="px-4 py-5 sm:p-6">
              {error() && (
                <div class="mb-4 rounded-lg bg-red-50 p-4">
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
              )}

              <div class="space-y-6">
                {/* Basic Information */}
                <div class="border-b border-gray-6 pb-6">
                  <h3 class="text-lg font-medium leading-6 text-gray-12">Basic Information</h3>
                  <p class="mt-1 text-sm text-gray-9">
                    Basic details about your OAuth2 client application.
                  </p>

                  <div class="mt-4 grid grid-cols-1 gap-6 sm:grid-cols-2">
                    <div>
                      <label for="client-id" class="block text-sm font-medium text-gray-11">
                        Client ID <span class="text-red-500">*</span>
                      </label>
                      <div class="mt-1">
                        <Input
                          type="text"
                          name="client-id"
                          id="client-id"
                          required
                          value={clientId()}
                          onInput={(e) => setClientId(e.target.value)}
                          placeholder="my-app-client"
                        />
                      </div>
                      <p class="mt-1 text-sm text-gray-8">A unique identifier for your client application.</p>
                    </div>

                    <div>
                      <label for="client-name" class="block text-sm font-medium text-gray-11">
                        Client Name <span class="text-red-500">*</span>
                      </label>
                      <div class="mt-1">
                        <Input
                          type="text"
                          name="client-name"
                          id="client-name"
                          required
                          value={clientName()}
                          onInput={(e) => setClientName(e.target.value)}
                          placeholder="My Application"
                        />
                      </div>
                      <p class="mt-1 text-sm text-gray-8">A human-readable name for your client application.</p>
                    </div>

                    <div>
                      <label for="client-type" class="block text-sm font-medium text-gray-11">
                        Client Type <span class="text-red-500">*</span>
                      </label>
                      <div class="mt-1">
                        <select
                          id="client-type"
                          name="client-type"
                          value={clientType()}
                          onChange={(e) => setClientType(e.currentTarget.value as 'confidential' | 'public')}
                          class="block w-full rounded-lg border-gray-6 px-3 py-2 text-sm focus:border-blue-500 focus:ring-blue-500"
                        >
                          <option value="confidential">Confidential</option>
                          <option value="public">Public</option>
                        </select>
                      </div>
                      <p class="mt-1 text-sm text-gray-8">
                        Confidential clients can securely store credentials. Public clients cannot.
                      </p>
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

                    {/* Grant Types */}
                    <div>
                      <label class="block text-sm font-medium text-gray-11">
                        Grant Types <span class="text-red-500">*</span>
                      </label>
                      <p class="mt-1 text-sm text-gray-8">
                        OAuth2 grant types that your client will use.
                      </p>
                      <div class="mt-2 space-y-2">
                        <For each={availableGrantTypes}>
                          {(grantType) => (
                            <label class="flex items-center">
                              <input
                                type="checkbox"
                                checked={grantTypes().includes(grantType)}
                                onChange={() => toggleGrantType(grantType)}
                                class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-6 rounded"
                              />
                              <span class="ml-2 text-sm text-gray-11">{grantType}</span>
                            </label>
                          )}
                        </For>
                      </div>
                    </div>

                    {/* Response Types */}
                    <div>
                      <label class="block text-sm font-medium text-gray-11">
                        Response Types <span class="text-red-500">*</span>
                      </label>
                      <p class="mt-1 text-sm text-gray-8">
                        OAuth2 response types that your client will use.
                      </p>
                      <div class="mt-2 space-y-2">
                        <For each={availableResponseTypes}>
                          {(responseType) => (
                            <label class="flex items-center">
                              <input
                                type="checkbox"
                                checked={responseTypes().includes(responseType)}
                                onChange={() => toggleResponseType(responseType)}
                                class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-6 rounded"
                              />
                              <span class="ml-2 text-sm text-gray-11">{responseType}</span>
                            </label>
                          )}
                        </For>
                      </div>
                    </div>

                    {/* Scope */}
                    <div>
                      <label for="scope" class="block text-sm font-medium text-gray-11">
                        Scope
                      </label>
                      <div class="mt-1">
                        <Input
                          type="text"
                          name="scope"
                          id="scope"
                          value={scope()}
                          onInput={(e) => setScope(e.target.value)}
                          placeholder="openid profile email"
                        />
                      </div>
                      <p class="mt-1 text-sm text-gray-8">
                        Space-separated list of scopes that your client will request.
                      </p>
                    </div>
                  </div>
                </div>

                <div class="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => navigate('/oauth2-clients')}
                    class="inline-flex justify-center rounded-lg border border-gray-6 bg-white py-2 px-4 text-sm font-medium text-gray-11 shadow-sm hover:bg-gray-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={saving()}
                    class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {saving() ? 'Registering...' : 'Register Client'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default CreateOAuth2Client;
