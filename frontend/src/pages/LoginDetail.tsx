import { Component, createSignal, onMount, Show, For } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import { loginApi, type Login, type TwoFactorMethod, type TwoFactorMethods } from '../api/login';
import { userApi, type User } from '../api/user';
import { twoFactorApi } from '../api/twoFactor';
import { deviceApi, type Device } from '../api/device';

const LoginDetail: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [login, setLogin] = createSignal<Login | null>(null);
  const [associatedUsers, setAssociatedUsers] = createSignal<User[]>([]);
  const [twoFactorMethodsResponse, setTwoFactorMethodsResponse] = createSignal<TwoFactorMethods>({ count: 0, methods: [] });
  const [twoFactorMethods, setTwoFactorMethods] = createSignal<TwoFactorMethod[]>([]);
  const [linkedDevices, setLinkedDevices] = createSignal<Device[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [successMessage, setSuccessMessage] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [loadingUsers, setLoadingUsers] = createSignal(true);
  const [loadingTwoFactorMethods, setLoadingTwoFactorMethods] = createSignal(true);
  const [loadingDevices, setLoadingDevices] = createSignal(true);
  const [processingMethod, setProcessingMethod] = createSignal<string | null>(null);
  const [deletingMethod, setDeletingMethod] = createSignal<string | null>(null);
  const [unlinkingDevice, setUnlinkingDevice] = createSignal<string | null>(null);
  const [showCreateModal, setShowCreateModal] = createSignal(false);
  const [selectedMethodType, setSelectedMethodType] = createSignal<string>('email');
  const [creatingMethod, setCreatingMethod] = createSignal(false);

  onMount(() => {
    fetchLogin();
    fetchAssociatedUsers();
    fetchTwoFactorMethods();
    fetchLinkedDevices();
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
      const response = await loginApi.get2FAMethods(params.id);
      setTwoFactorMethodsResponse(response);
      setTwoFactorMethods(response.methods || []);
    } catch (err) {
      console.error('Failed to fetch 2FA methods:', err);
    } finally {
      setLoadingTwoFactorMethods(false);
    }
  };

  const fetchLinkedDevices = async () => {
    try {
      const devices = await deviceApi.listDevicesByLogin(params.id);
      setLinkedDevices(devices);
    } catch (err) {
      console.error('Failed to fetch linked devices:', err);
    } finally {
      setLoadingDevices(false);
    }
  };

  const toggleTwoFactorMethod = async (methodType: string, currentStatus: boolean) => {
    setProcessingMethod(methodType);
    setError(null);
    setSuccessMessage(null);
    
    try {
      if (currentStatus) {
        // Disable the method
        await twoFactorApi.disable2FAMethod(params.id, methodType);
        setSuccessMessage(`${getMethodDisplayName(methodType)} two-factor authentication has been disabled.`);
      } else {
        // Enable the method
        await twoFactorApi.enable2FAMethod(params.id, methodType);
        setSuccessMessage(`${getMethodDisplayName(methodType)} two-factor authentication has been enabled.`);
      }
      // Refresh the 2FA methods list
      await fetchTwoFactorMethods();
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      console.error(`Failed to ${currentStatus ? 'disable' : 'enable'} 2FA method:`, err);
      setError(err instanceof Error ? err.message : `Failed to ${currentStatus ? 'disable' : 'enable'} 2FA method`);
    } finally {
      setProcessingMethod(null);
    }
  };

  const deleteTwoFactorMethod = async (method: TwoFactorMethod) => {
    if (!confirm(`Are you sure you want to delete the ${getMethodDisplayName(method.type)} two-factor authentication method?`)) {
      return;
    }
    
    setDeletingMethod(method.type);
    setError(null);
    setSuccessMessage(null);
    
    try {
      await twoFactorApi.delete2FAMethod(params.id, method.type, method.two_factor_id);
      setSuccessMessage(`${getMethodDisplayName(method.type)} two-factor authentication has been deleted.`);
      
      // Refresh the 2FA methods list
      await fetchTwoFactorMethods();
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      console.error(`Failed to delete 2FA method:`, err);
      setError(err instanceof Error ? err.message : `Failed to delete 2FA method`);
    } finally {
      setDeletingMethod(null);
    }
  };
  
  const getMethodDisplayName = (methodType: string): string => {
    switch (methodType) {
      case 'email': return 'Email';
      case 'totp': return 'Authenticator App';
      case 'sms': return 'SMS';
      case 'authenticator_app': return 'Authenticator App';
      default: return methodType;
    }
  };
  
  const createTwoFactorMethod = async () => {
    setCreatingMethod(true);
    setError(null);
    setSuccessMessage(null);
    
    try {
      await twoFactorApi.create2FAMethod(params.id, selectedMethodType());
      setSuccessMessage(`${getMethodDisplayName(selectedMethodType())} two-factor authentication method has been created.`);
      
      // Refresh the 2FA methods list
      await fetchTwoFactorMethods();
      
      // Close the modal
      setShowCreateModal(false);
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      console.error(`Failed to create 2FA method:`, err);
      setError(err instanceof Error ? err.message : `Failed to create 2FA method`);
    } finally {
      setCreatingMethod(false);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const isExpiringSoon = (dateString: string) => {
    if (!dateString) return false;
    
    const expiryDate = new Date(dateString);
    const now = new Date();
    
    // Calculate the difference in days
    const diffTime = expiryDate.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    // Return true if expiring within 7 days
    return diffDays > 0 && diffDays <= 7;
  };

  const handleUnlinkDevice = async (fingerprint: string) => {
    setUnlinkingDevice(fingerprint);
    setError(null);
    setSuccessMessage(null);
    
    try {
      await deviceApi.unlinkDeviceFromLogin(params.id, fingerprint);
      setSuccessMessage('Device unlinked successfully');
      
      // Refresh the linked devices list
      await fetchLinkedDevices();
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unlink device');
      
      // Clear error message after 5 seconds
      setTimeout(() => setError(null), 5000);
    } finally {
      setUnlinkingDevice(null);
    }
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
      
      <Show when={successMessage()}>
        <div class="mt-4 bg-green-50 p-4 rounded-lg">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-green-800">{successMessage()}</h3>
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

          {/* Placeholder for when no 2FA methods are configured - now handled by the twoFactorMethodsResponse().count === 0 condition below */}

          <Show when={!loadingTwoFactorMethods() && twoFactorMethodsResponse().count > 0 && twoFactorMethods().length > 0}>
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
                          {getMethodDisplayName(method.type)}
                        </td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                          <span class={`inline-flex items-center rounded-md px-2.5 py-0.5 text-sm font-medium ${method.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                            {method.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </td>
                        <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                          <div class="flex justify-end space-x-2">
                            <button
                              onClick={() => toggleTwoFactorMethod(method.type, method.enabled)}
                              disabled={processingMethod() === method.type || deletingMethod() === method.type}
                              class={`px-3 py-1 rounded-md text-sm font-medium ${method.enabled 
                                ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                                : 'bg-green-100 text-green-700 hover:bg-green-200'} 
                                ${(processingMethod() === method.type || deletingMethod() === method.type) ? 'opacity-50 cursor-not-allowed' : ''}`}
                            >
                              {processingMethod() === method.type 
                                ? 'Processing...' 
                                : method.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              onClick={() => deleteTwoFactorMethod(method)}
                              disabled={processingMethod() === method.type || deletingMethod() === method.type}
                              class={`px-3 py-1 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500
                                ${(processingMethod() === method.type || deletingMethod() === method.type) ? 'opacity-50 cursor-not-allowed' : ''}`}
                            >
                              {deletingMethod() === method.type ? 'Deleting...' : 'Delete'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
            
            <div class="mt-4 flex justify-end">
              <button
                onClick={() => setShowCreateModal(true)}
                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Add 2FA Method
              </button>
            </div>
          </Show>
          
          <Show when={!loadingTwoFactorMethods() && twoFactorMethodsResponse().count === 0}>
            <div class="mt-4 rounded-md bg-yellow-50 p-4">
              <div class="flex">
                <div class="flex-shrink-0">
                  <svg class="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
                  </svg>
                </div>
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-yellow-800">No two-factor authentication methods configured</h3>
                  <div class="mt-2 text-sm text-yellow-700">
                    <p>This login doesn't have any two-factor authentication methods configured. Add a method to enhance security.</p>
                  </div>
                </div>
              </div>
            </div>
            <div class="mt-4 flex justify-end">
              <button
                onClick={() => setShowCreateModal(true)}
                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Add 2FA Method
              </button>
            </div>
          </Show>
        </div>

        {/* Linked Devices Section */}
        <Show when={!loading()}>
          <div class="bg-white shadow sm:rounded-lg mt-6">
            <div class="px-4 py-5 sm:px-6 flex justify-between items-center">
              <div>
                <h3 class="text-lg leading-6 font-medium text-gray-900">Linked Devices</h3>
                <p class="mt-1 max-w-2xl text-sm text-gray-500">Devices that are trusted for this login</p>
              </div>
            </div>
            
            <Show when={loadingDevices()}>
              <div class="px-4 py-5 sm:p-6">
                <p class="text-sm text-gray-500">Loading devices...</p>
              </div>
            </Show>
            
            <Show when={!loadingDevices() && linkedDevices().length === 0}>
              <div class="px-4 py-5 sm:p-6 border-t border-gray-200">
                <p class="text-sm text-gray-500">No devices linked to this login.</p>
              </div>
            </Show>
            
            <Show when={!loadingDevices() && linkedDevices().length > 0}>
              <div class="border-t border-gray-200">
                <div class="overflow-x-auto">
                  <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                      <tr>
                        <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Fingerprint</th>
                        <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Last Login</th>
                        <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Expires</th>
                        <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                          <span class="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                      <For each={linkedDevices()}>
                        {(device) => (
                          <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                              <div class="flex flex-col">
                                <span class="font-mono">{device.fingerprint.substring(0, 16)}...</span>
                                <span class="text-xs text-gray-500">{device.user_agent || 'Unknown device'}</span>
                              </div>
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                              {formatDate(device.last_login)}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm">
                              <span class={`${isExpiringSoon(device.expires_at || '') ? 'text-yellow-600' : 'text-gray-500'}`}>
                                {formatDate(device.expires_at)}
                              </span>
                            </td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                              <button
                                onClick={() => handleUnlinkDevice(device.fingerprint)}
                                disabled={unlinkingDevice() === device.fingerprint}
                                class="text-red-600 hover:text-red-900 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                {unlinkingDevice() === device.fingerprint ? 'Unlinking...' : 'Unlink'}
                                <span class="sr-only">, {device.fingerprint}</span>
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </div>
            </Show>
          </div>
        </Show>
        
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
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.257 3.099zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
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
      
      {/* Create 2FA Method Modal */}
      <Show when={showCreateModal()}>
        <div class="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            {/* Background overlay */}
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true" onClick={() => setShowCreateModal(false)}></div>

            {/* Modal panel */}
            <div class="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div>
                <div class="mt-3 text-center sm:mt-5">
                  <h3 class="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                    Add Two-Factor Authentication Method
                  </h3>
                  <div class="mt-4">
                    <label for="method-type" class="block text-sm font-medium text-gray-700 text-left">
                      Method Type
                    </label>
                    <select
                      id="method-type"
                      name="method-type"
                      class="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
                      value={selectedMethodType()}
                      onChange={(e) => setSelectedMethodType(e.target.value)}
                    >
                      <option value="email">Email</option>
                      <option value="sms">SMS</option>
                    </select>
                  </div>
                </div>
              </div>
              <div class="mt-5 sm:mt-6 sm:grid sm:grid-cols-2 sm:gap-3 sm:grid-flow-row-dense">
                <button
                  type="button"
                  class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:col-start-2 sm:text-sm"
                  onClick={createTwoFactorMethod}
                  disabled={creatingMethod()}
                >
                  {creatingMethod() ? 'Creating...' : 'Create'}
                </button>
                <button
                  type="button"
                  class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:col-start-1 sm:text-sm"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default LoginDetail;
