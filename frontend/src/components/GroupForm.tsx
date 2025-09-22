import { Component, createEffect, createSignal, onMount, For } from 'solid-js';
import type { Group, GroupUser } from '../api/groups';
import { groupsApi } from '../api/groups';
import { userApi, type User } from '../api/user';
import { Input } from './ui/input';

interface Props {
  initialData?: Group;
  submitLabel?: string;
  onSubmit?: (data: { name: string; description?: string }) => Promise<void>;
  onError?: (error: Error) => void;
}

const GroupForm: Component<Props> = (props) => {
  const [name, setName] = createSignal(props.initialData?.name || '');
  const [description, setDescription] = createSignal(props.initialData?.description || '');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [users, setUsers] = createSignal<GroupUser[]>([]);
  const [allUsers, setAllUsers] = createSignal<User[]>([]);
  const [selectedUserId, setSelectedUserId] = createSignal<string>('');
  const [addingUser, setAddingUser] = createSignal(false);
  const [successMessage, setSuccessMessage] = createSignal<string | null>(null);

  // Update form when initialData changes
  createEffect(() => {
    if (props.initialData) {
      setName(props.initialData.name || '');
      setDescription(props.initialData.description || '');
    }
  });

  const loadUsers = async () => {
    const groupId = props.initialData?.id;
    
    if (groupId) {
      try {
        const groupUsers = await groupsApi.getGroupUsers(groupId);
        setUsers(groupUsers || []);
      } catch (error) {
        console.error('Failed to fetch group users:', error);
        props.onError?.(error as Error);
      }
    }
  };

  const loadAllUsers = async () => {
    try {
      const allUsersList = await userApi.listUsers();
      setAllUsers(allUsersList || []);
    } catch (error) {
      console.error('Failed to fetch all users:', error);
      props.onError?.(error as Error);
    }
  };

  onMount(() => {
    loadUsers();
    if (props.initialData?.id) {
      loadAllUsers();
    }
  });

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    console.log('GroupForm: Form submitted');
    console.log('GroupForm: Name value:', name());
    console.log('GroupForm: Description value:', description());
    
    setError(null);
    setLoading(true);

    try {
      const submitData = {
        name: name(),
        description: description().trim() || undefined
      };
      console.log('GroupForm: Calling onSubmit with data:', submitData);
      await props.onSubmit?.(submitData);
      console.log('GroupForm: onSubmit completed successfully');
    } catch (err) {
      console.error('GroupForm: Error during submission:', err);
      setError((err as Error).message);
      props.onError?.(err as Error);
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveUser = async (user: GroupUser) => {
    const groupId = props.initialData?.id;
    const userId = user.id;
    
    if (!groupId || !userId) return;

    // Show confirmation dialog
    const userName = user.name || user.email || user.username;
    if (!window.confirm(`Are you sure you want to remove ${userName} from this group? This action cannot be undone.`)) {
      return;
    }

    try {
      await groupsApi.removeUserFromGroup(groupId, userId);
      // Refresh the users list
      await loadUsers();
      setSuccessMessage(`User ${userName} removed from group successfully!`);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (error) {
      console.error('Failed to remove user from group:', error);
      props.onError?.(error as Error);
    }
  };

  const handleAddUser = async () => {
    const groupId = props.initialData?.id;
    const userId = selectedUserId();
    
    if (!groupId || !userId) return;

    setAddingUser(true);
    try {
      await groupsApi.addUserToGroup(groupId, userId);
      // Refresh the users list
      await loadUsers();
      setSelectedUserId('');
      
      // Find the added user's name for success message
      const addedUser = allUsers().find(u => u.id === userId);
      const userName = addedUser?.name || addedUser?.email || addedUser?.username || 'User';
      setSuccessMessage(`User ${userName} added to group successfully!`);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (error) {
      console.error('Failed to add user to group:', error);
      props.onError?.(error as Error);
    } finally {
      setAddingUser(false);
    }
  };

  // Get users that are not already in the group
  const availableUsers = () => {
    const groupUserIds = new Set((users() || []).map(u => u.id));
    return (allUsers() || []).filter(user => !groupUserIds.has(user.id));
  };

  return (
    <form onSubmit={handleSubmit} class="space-y-6">
      <div class="max-w-lg space-y-4">
        <div>
          <label class="block text-base font-medium text-gray-700 mb-2">Group Name</label>
          <Input
            type="text"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            class="w-full border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base"
            required
          />
        </div>
        
        <div>
          <label class="block text-base font-medium text-gray-700 mb-2">Description</label>
          <textarea
            value={description()}
            onInput={(e) => setDescription(e.currentTarget.value)}
            class="w-full border-gray-300 rounded-md shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base"
            rows="3"
            placeholder="Enter group description (optional)"
          />
        </div>
        
        <div class="flex justify-end">
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

      {successMessage() && (
        <div class="rounded-md bg-green-50 p-4">
          <div class="text-sm text-green-700">{successMessage()}</div>
        </div>
      )}

      {props.initialData && (
        <div class="mt-8">
          <h3 class="text-lg font-medium text-gray-900 mb-6">Users in this Group</h3>
          
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Add User to Group
            </label>
            <div class="flex space-x-3">
              <div class="flex-1">
                <select
                  value={selectedUserId()}
                  onChange={(e) => setSelectedUserId(e.currentTarget.value)}
                  class="block w-full appearance-none rounded-lg border border-gray-300 px-3 py-2 placeholder-gray-500 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  disabled={addingUser()}
                >
                  <option value="">Select a user to add...</option>
                  <For each={availableUsers()}>
                    {(user) => (
                      <option value={user.id}>
                        {user.name || user.email || user.username}
                      </option>
                    )}
                  </For>
                </select>
              </div>
              <button
                type="button"
                onClick={handleAddUser}
                disabled={!selectedUserId() || addingUser()}
                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {addingUser() ? 'Adding...' : 'Add User'}
              </button>
            </div>
            <p class="mt-1 text-sm text-gray-500">
              Select a user from the dropdown to add them to this group
            </p>
          </div>
          <div class="mt-4">
            {(users() || []).length > 0 ? (
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
                    {(users() || []).map((user) => (
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
              <p class="text-gray-500">No users have been assigned to this group.</p>
            )}
          </div>
        </div>
      )}
    </form>
  );
};

export default GroupForm;
