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
  const [contacts, setContacts] = createSignal<string[]>([]);

  // Form fields
  const [clientName, setClientName] = createSignal('');
  const [clientType, setClientType] = createSignal<'confidential' | 'public'>('confidential');
  const [responseTypes, setResponseTypes] = createSignal<string[]>(['code']);
  const [grantTypes, setGrantTypes] = createSignal<string[]>(['authorization_code']);
  const [scope, setScope] = createSignal('');
  const [clientUri, setClientUri] = createSignal('');
  const [logoUri, setLogoUri] = createSignal('');
  const [tosUri, setTosUri] = createSignal('');
  const [policyUri, setPolicyUri] = createSignal('');
  const [jwksUri, setJwksUri] = createSignal('');
  const [softwareId, setSoftwareId] = createSignal('');
  const [softwareVersion, setSoftwareVersion] = createSignal('');
  const [description, setDescription] = createSignal('');
  const [tokenEndpointAuthMethod, setTokenEndpointAuthMethod] = createSignal('client_secret_basic');

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
      setClientUri(clientData.client_uri || '');
      setLogoUri(clientData.logo_uri || '');
      setContacts(clientData.contacts || []);
      setTosUri(clientData.tos_uri || '');
      setPolicyUri(clientData.policy_uri || '');
      setJwksUri(clientData.jwks_uri || '');
      setSoftwareId(clientData.software_id || '');
      setSoftwareVersion(clientData.software_version || '');
      setDescription(clientData.description || '');
      setTokenEndpointAuthMethod(clientData.token_endpoint_auth_method || 'client_secret_basic');
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

  const addContact = () => {
    setContacts([...contacts(), '']);
  };

  const updateContact = (index: number, value: string) => {
    const contactList = [...contacts()];
    contactList[index] = value;
    setContacts(contactList);
  };

  const removeContact = (index: number) => {
    setContacts(contacts().filter((_, i) => i !== index));
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
      const updateData: OAuth2ClientUpdateRequest = {
        client_name: clientName(),
        redirect_uris: redirectUris().filter(uri => uri.trim() !== ''),
        client_type: clientType(),
        response_types: responseTypes(),
        grant_types: grantTypes(),
        scope: scope() || undefined,
        client_uri: clientUri() || undefined,
        logo_uri: logoUri() || undefined,
        contacts: contacts().filter(contact => contact.trim() !== ''),
        tos_uri: tosUri() || undefined,
        policy_uri: policyUri() || undefined,
        jwks_uri: jwksUri() || undefined,
        software_id: softwareId() || undefined,
        software_version: softwareVersion() || undefined,
        description: description() || undefined,
        token_endpoint_auth_method: tokenEndpointAuthMethod(),
      };

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
            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
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
                {['code'].map((type) => (
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
                {['authorization_code'].map((type) => (
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

            {/* Optional Fields */}
            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
              <div>
                <label class="block text-sm font-medium text-gray-700">Scope</label>
                <input
                  type="text"
                  value={scope()}
                  onInput={(e) => setScope(e.currentTarget.value)}
                  placeholder="openid profile email"
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Token Endpoint Auth Method</label>
                <select
                  value={tokenEndpointAuthMethod()}
                  onChange={(e) => setTokenEndpointAuthMethod(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="client_secret_basic">Client Secret Basic</option>
                  <option value="client_secret_post">Client Secret Post</option>
                  <option value="none">None</option>
                </select>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Client URI</label>
                <input
                  type="text"
                  value={clientUri()}
                  onInput={(e) => setClientUri(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Logo URI</label>
                <input
                  type="url"
                  value={logoUri()}
                  onInput={(e) => setLogoUri(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Terms of Service URI</label>
                <input
                  type="url"
                  value={tosUri()}
                  onInput={(e) => setTosUri(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Policy URI</label>
                <input
                  type="url"
                  value={policyUri()}
                  onInput={(e) => setPolicyUri(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">JWKS URI</label>
                <input
                  type="url"
                  value={jwksUri()}
                  onInput={(e) => setJwksUri(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Software ID</label>
                <input
                  type="text"
                  value={softwareId()}
                  onInput={(e) => setSoftwareId(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Software Version</label>
                <input
                  type="text"
                  value={softwareVersion()}
                  onInput={(e) => setSoftwareVersion(e.currentTarget.value)}
                  class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>

            {/* Contacts */}
                    <div class="sm:col-span-2">
                      <label class="block text-sm font-medium text-gray-11">
                        Contact Emails
                      </label>
                      <p class="mt-1 text-sm text-gray-8">
                        Email addresses for people responsible for this client.
                      </p>
                    <div class="mt-2 space-y-2">
                      <Index each={contacts()}>
                        {(contact, i) => (
                          <div class="flex items-center space-x-2">
                            <Input
                              type="email"
                              value={contact()}                                   // accessor from <Index>
                              onInput={(e) => updateContact(i, e.currentTarget.value)} // no casting
                              placeholder="admin@example.com"
                              class="flex-1"
                            />
                             <button
                            type="button"
                            onClick={() => removeContact(i)}
                            class="px-3 py-2 text-red-600 hover:text-red-800"
                          >
                            Remove
                          </button>
                          </div>
                        )}
                       
                      </Index>

                      <button
                        type="button"
                        onClick={addContact}
                        class="inline-flex items-center rounded-lg bg-gray-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-gray-500"
                      >
                        Add Contact
                      </button>
                    </div>
                    </div>

            {/* Description */}
            <div>
              <label class="block text-sm font-medium text-gray-700">Description</label>
              <textarea
                value={description()}
                onInput={(e) => setDescription(e.currentTarget.value)}
                rows={3}
                class="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              />
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
