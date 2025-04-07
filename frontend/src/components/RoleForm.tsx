import { Component, createEffect, createSignal, onMount } from 'solid-js';
import type { Role, RoleUser } from '../api/role';
import { roleApi } from '../api/role';
import { Input } from './ui/input';

interface Props {
  initialData?: Role;
  submitLabel?: string;
  onSubmit?: (data: { name: string }) => Promise<void>;
  onError?: (error: Error) => void;
}

const RoleForm: Component<Props> = (props) => {
  const [name, setName] = createSignal(props.initialData?.name || '');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [users, setUsers] = createSignal<RoleUser[]>([]);

  // Update form when initialData changes
  createEffect(() => {
    if (props.initialData) {
      setName(props.initialData.name);
    }
  });

  const loadUsers = async () => {
    // Use initialData.id if uuid is not available
    const roleId = props.initialData?.uuid || props.initialData?.id;
    
    if (roleId) {
      try {
        const roleUsers = await roleApi.getRoleUsers(roleId);
        setUsers(roleUsers);
      } catch (error) {
        console.error('Failed to fetch role users:', error);
        props.onError?.(error as Error);
      }
    }
  };

  onMount(loadUsers);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    console.log('RoleForm: Form submitted');
    console.log('RoleForm: Name value:', name());
    
    setError(null);
    setLoading(true);

    try {
      console.log('RoleForm: Calling onSubmit with data:', { name: name() });
      await props.onSubmit?.({ name: name() });
      console.log('RoleForm: onSubmit completed successfully');
    } catch (err) {
      console.error('RoleForm: Error during submission:', err);
      setError((err as Error).message);
      props.onError?.(err as Error);
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveUser = async (user: RoleUser) => {
    // Use initialData.uuid if available, otherwise fall back to initialData.id
    const roleId = props.initialData?.uuid || props.initialData?.id;
    const userId = user.uuid || user.id;
    
    if (!roleId || !userId) return;

    // Show confirmation dialog
    const userName = user.name || user.email || user.username;
    if (!window.confirm(`Are you sure you want to remove ${userName} from this role? This action cannot be undone.`)) {
      return;
    }

    try {
      await roleApi.removeUserFromRole(roleId, userId);
      // Refresh the users list
      await loadUsers();
    } catch (error) {
      console.error('Failed to remove user from role:', error);
      props.onError?.(error as Error);
    }
  };

  return (
    <form onSubmit={handleSubmit} class="space-y-6">
      <div class="max-w-lg">
        <label class="block text-base font-medium text-gray-700 mb-2">Role Name</label>
        <div class="flex space-x-4">
          <Input
            type="text"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            class="flex-1 border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base"
            required
          />
          <button
            type="submit"
            disabled={loading()}
            class="inline-flex items-center px-4 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
          >
            {loading() ? 'Loading...' : props.submitLabel}
          </button>
        </div>
      </div>

      {error() && (
        <div class="rounded-md bg-red-50 p-4">
          <div class="text-sm text-red-700">{error()}</div>
        </div>
      )}

      {props.initialData && (
        <div class="mt-8">
          <h3 class="text-lg font-medium text-gray-900">Users with this Role</h3>
          <div class="mt-4">
            {users().length > 0 ? (
              <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-300">
                  <thead class="bg-gray-50">
                    <tr>
                      <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">
                        Email
                      </th>
                      <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                        Name
                      </th>
                      <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                        Username
                      </th>
                      <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                        <span class="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-gray-200 bg-white">
                    {users().map((user) => (
                      <tr>
                        <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                          {user.email}
                        </td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{user.name}</td>
                        <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{user.username}</td>
                        <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                          <button
                            type="button"
                            onClick={() => handleRemoveUser(user)}
                            class="text-red-600 hover:text-red-900"
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p class="text-gray-500">No users have been assigned this role.</p>
            )}
          </div>
        </div>
      )}
    </form>
  );
};

export default RoleForm;
