import { Component, createResource, createSignal, For, onMount, Show } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import { groupsApi, type Group, type GroupUser } from '../api/groups';

const GroupUsers: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [users, setUsers] = createSignal<GroupUser[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  const [group] = createResource<Group>(() => {
    if (!params.id) throw new Error('No group ID provided');
    return groupsApi.getGroup(params.id);
  });

  const fetchUsers = async () => {
    if (!params.id) return;
    
    try {
      setError(null);
      const data = await groupsApi.getGroupUsers(params.id);
      setUsers(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch group users');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveUser = async (user: GroupUser) => {
    if (!params.id) return;
    
    const userName = user.name || user.email || user.username;
    if (!confirm(`Are you sure you want to remove ${userName} from this group?`)) return;
    
    try {
      await groupsApi.removeUserFromGroup(params.id, user.id!);
      setUsers(users().filter(u => u.id !== user.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove user from group');
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString();
  };

  onMount(() => {
    fetchUsers();
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <div class="flex items-center space-x-2">
            <button
              onClick={() => navigate('/groups')}
              class="text-blue-600 hover:text-blue-800"
            >
              ← Groups
            </button>
            <span class="text-gray-400">/</span>
            <h1 class="text-2xl font-semibold text-gray-11">
              <Show when={group()} fallback="Group Users">
                {group()?.name} Users
              </Show>
            </h1>
          </div>
          <p class="mt-2 text-sm text-gray-9">
            <Show when={group()} fallback="Manage users in this group.">
              Manage users in the "{group()?.name}" group.
            </Show>
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            type="button"
            onClick={() => navigate(`/groups/${params.id}/edit`)}
            class="inline-flex items-center justify-center rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 sm:w-auto"
          >
            Edit Group
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

      <Show when={group() && group()?.description}>
        <div class="mt-4 bg-blue-50 p-4 rounded-lg">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-sm text-blue-800">{group()?.description}</p>
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
                      Email
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Name
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Username
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-6">
                  <Show when={!loading()} fallback={<tr><td colspan="4" class="text-center py-4">Loading...</td></tr>}>
                    <Show when={users().length > 0} fallback={
                      <tr>
                        <td colspan="4" class="text-center py-8 text-gray-500">
                          No users have been assigned to this group.
                        </td>
                      </tr>
                    }>
                      <For each={users()}>
                        {(user) => (
                          <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                              {user.email || '-'}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              {user.name || '-'}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                              {user.username || '-'}
                            </td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                              <button
                                onClick={() => handleRemoveUser(user)}
                                class="text-red-600 hover:text-red-900"
                              >
                                Remove
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </Show>
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

export default GroupUsers;
