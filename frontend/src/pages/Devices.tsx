import { useNavigate } from '@solidjs/router';
import { Component, createSignal, For, onMount, Show } from 'solid-js';
import { deviceApi, type Device } from '../api/device';
import { Button } from '@/components/ui/button';
import { 
  Dialog,
  DialogContent,
  DialogTitle
} from '@/components/ui/dialog';
import { loginApi, type Login } from '../api/login';

const Devices: Component = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = createSignal<Device[]>([]);
  const [logins, setLogins] = createSignal<Login[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [isAddDeviceOpen, setIsAddDeviceOpen] = createSignal(false);
  const [isLinkLoginOpen, setIsLinkLoginOpen] = createSignal(false);
  const [selectedLoginId, setSelectedLoginId] = createSignal<string>('');
  const [selectedFingerprint, setSelectedFingerprint] = createSignal<string>('');
  const [newFingerprint, setNewFingerprint] = createSignal('');
  const [newUserAgent, setNewUserAgent] = createSignal('');
  const [addingDevice, setAddingDevice] = createSignal(false);
  const [linkingDevice, setLinkingDevice] = createSignal(false);

  const fetchDevices = async () => {
    try {
      const data = await deviceApi.listDevices();
      setDevices(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch devices');
    } finally {
      setLoading(false);
    }
  };

  const fetchLogins = async () => {
    try {
      const data = await loginApi.listLogins();
      setLogins(data);
    } catch (err) {
      console.error('Failed to fetch logins:', err);
      // Don't set error here to avoid disrupting the main UI
    }
  };

  const handleAddDevice = async () => {
    if (!newFingerprint()) {
      setError('Fingerprint is required');
      return;
    }

    setAddingDevice(true);
    try {
      const device = await deviceApi.registerDevice(newFingerprint(), newUserAgent());
      setDevices([...devices(), device]);
      setIsAddDeviceOpen(false);
      setNewFingerprint('');
      setNewUserAgent('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add device');
    } finally {
      setAddingDevice(false);
    }
  };

  const openLinkDialog = (fingerprint: string) => {
    setSelectedFingerprint(fingerprint);
    setSelectedLoginId('');
    setIsLinkLoginOpen(true);
    // Fetch logins when opening the dialog
    fetchLogins();
  };

  const handleLinkDevice = async () => {
    if (!selectedLoginId()) {
      setError('Please select a login');
      return;
    }

    setLinkingDevice(true);
    try {
      // We'll need to modify the API to accept a login ID parameter
      await deviceApi.linkDevice(selectedFingerprint(), selectedLoginId());
      setIsLinkLoginOpen(false);
      // Refresh the list to show updated status
      fetchDevices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to link device');
    } finally {
      setLinkingDevice(false);
    }
  };

  onMount(() => {
    fetchDevices();
  });

  const formatDate = (dateString: string) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString();
  };

  // Helper function to render linked logins
  const renderLinkedLogins = (device: Device) => {
    if (!device.linked_logins || device.linked_logins.length === 0) {
      return <span class="text-gray-8">Not linked</span>;
    }

    return (
      <div class="flex flex-col gap-1">
        {device.linked_logins.map(login => (
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
            {login.username}
          </span>
        ))}
      </div>
    );
  };

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">Devices</h1>
          <p class="mt-2 text-sm text-gray-9">
            A list of all registered devices in the system including their fingerprint, user agent, and last login time.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <Button
            onClick={() => setIsAddDeviceOpen(true)}
            class="inline-flex items-center justify-center rounded-lg border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 sm:w-auto"
          >
            Add Device
          </Button>
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
              <Button
                variant="ghost"
                class="mt-2 text-sm text-red-800"
                onClick={() => setError(null)}
              >
                Dismiss
              </Button>
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
                      Fingerprint
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      User Agent
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Linked Logins
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Last Login
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Created At
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-6">
                  <Show when={!loading()} fallback={<tr><td colspan="5" class="text-center py-4">Loading...</td></tr>}>
                    {devices().length === 0 ? (
                      <tr>
                        <td colspan="5" class="text-center py-4 text-sm text-gray-9">No devices found</td>
                      </tr>
                    ) : (
                      <For each={devices()}>
                        {(device) => (
                          <tr data-key={device.id}>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                              {device.fingerprint.substring(0, 16)}...
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              <div class="max-w-xs truncate" title={device.user_agent}>
                                {device.user_agent}
                              </div>
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              {renderLinkedLogins(device)}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              {formatDate(device.last_login)}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              {formatDate(device.created_at)}
                            </td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                              <Button
                                onClick={() => openLinkDialog(device.fingerprint)}
                                class="text-blue-600 hover:text-blue-900"
                                variant="ghost"
                              >
                                Link to Login
                              </Button>
                            </td>
                          </tr>
                        )}
                      </For>
                    )}
                  </Show>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Add Device Dialog */}
      <Dialog open={isAddDeviceOpen()} onOpenChange={setIsAddDeviceOpen}>
        <DialogContent>
          <DialogTitle class="text-lg font-medium text-gray-12 mb-4">Add New Device</DialogTitle>
          
          <div class="mb-4">
            <label class="block text-sm font-medium text-gray-11 mb-1">
              Fingerprint
            </label>
            <input
              type="text"
              value={newFingerprint()}
              onInput={(e) => setNewFingerprint(e.target.value)}
              class="w-full px-3 py-2 border border-gray-6 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter device fingerprint"
            />
          </div>
          
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-11 mb-1">
              User Agent (optional)
            </label>
            <input
              type="text"
              value={newUserAgent()}
              onInput={(e) => setNewUserAgent(e.target.value)}
              class="w-full px-3 py-2 border border-gray-6 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter user agent"
            />
          </div>
          
          <div class="flex justify-end space-x-3">
            <Button
              variant="outline"
              onClick={() => setIsAddDeviceOpen(false)}
              disabled={addingDevice()}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddDevice}
              disabled={addingDevice() || !newFingerprint()}
            >
              {addingDevice() ? 'Adding...' : 'Add Device'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Link to Login Dialog */}
      <Dialog open={isLinkLoginOpen()} onOpenChange={setIsLinkLoginOpen}>
        <DialogContent>
          <DialogTitle class="text-lg font-medium text-gray-12 mb-4">Link Device to Login</DialogTitle>
          
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-11 mb-1">
              Select Login
            </label>
            <select
              value={selectedLoginId()}
              onChange={(e) => setSelectedLoginId(e.target.value)}
              class="w-full px-3 py-2 border border-gray-6 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">Select a login...</option>
              <For each={logins()}>
                {(login) => (
                  <option value={login.id}>{login.username}</option>
                )}
              </For>
            </select>
          </div>
          
          <div class="flex justify-end space-x-3">
            <Button
              variant="outline"
              onClick={() => setIsLinkLoginOpen(false)}
              disabled={linkingDevice()}
            >
              Cancel
            </Button>
            <Button
              onClick={handleLinkDevice}
              disabled={linkingDevice() || !selectedLoginId()}
            >
              {linkingDevice() ? 'Linking...' : 'Link Device'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default Devices;
