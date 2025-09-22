import { useNavigate } from '@solidjs/router';
import { Component, createSignal, For, onMount, Show } from 'solid-js';
import type { Group } from '../api/groups';
import { groupsApi } from '../api/groups';

const Groups: Component = () => {
  const navigate = useNavigate();
  const [groups, setGroups] = createSignal<Group[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [showCreateModal, setShowCreateModal] = createSignal(false);
  const [createForm, setCreateForm] = createSignal({ name: '', description: '' });
  const [creating, setCreating] = createSignal(false);
  const [successMessage, setSuccessMessage] = createSignal<string | null>(null);

  const fetchGroups = async () => {
    try {
      setError(null);
      const data = await groupsApi.listGroups();
      setGroups(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch groups');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete the group "${name}"?`)) return;
    
    try {
      await groupsApi.deleteGroup(id);
      setGroups(groups().filter(group => group?.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete group');
    }
  };

  const handleCreateGroup = async (e: Event) => {
    e.preventDefault();
    setCreating(true);
    setError(null);

    try {
      const form = createForm();
      if (!form.name.trim()) {
        setError('Group name is required');
        return;
      }

      const newGroup = await groupsApi.createGroup({
        name: form.name.trim(),
        description: form.description.trim() || undefined
      });

      setGroups([...groups(), newGroup]);
      setShowCreateModal(false);
      setCreateForm({ name: '', description: '' });
      setSuccessMessage(`Group "${newGroup.name}" created successfully!`);
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create group');
    } finally {
      setCreating(false);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString();
  };

  onMount(() => {
    fetchGroups();
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-11">Groups</h1>
          <p class="mt-2 text-sm text-gray-9">
            A list of all groups in the system including their name, description, and creation date.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            class="inline-flex items-center justify-center rounded-lg border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 sm:w-auto"
          >
            Add group
          </button>
        </div>
      </div>

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

      <div class="mt-8 flex flex-col">
        <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
              <table class="min-w-full divide-y divide-gray-6">
                <thead>
                  <tr>
                    <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-11 sm:pl-6">
                      Name
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Description
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Created
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-11">
                      Updated
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-6">
                  <Show when={!loading()} fallback={<tr><td colspan="5" class="text-center py-4">Loading...</td></tr>}>
                    <For each={groups()}>
                      {(group) => (
                        <tr>
                          <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-11 sm:pl-6">
                            <button
                              onClick={() => navigate(`/groups/${group.id}/users`)}
                              class="text-blue-600 hover:text-blue-800 hover:underline"
                            >
                              {group.name || '-'}
                            </button>
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {group.description || '-'}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {formatDate(group.created_at)}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-11">
                            {formatDate(group.updated_at)}
                          </td>
                          <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                            <button
                              onClick={() => navigate(`/groups/${group.id}/edit`)}
                              class="text-blue-600 hover:text-blue-900 mr-4"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => handleDelete(group.id!, group.name!)}
                              class="text-red-600 hover:text-red-900"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      )}
                    </For>
                  </Show>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Create Group Modal */}
      <Show when={showCreateModal()}>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mt-3">
              <h3 class="text-lg font-medium text-gray-900 mb-4">Create New Group</h3>
              <form onSubmit={handleCreateGroup}>
                <div class="mb-4">
                  <label for="groupName" class="block text-sm font-medium text-gray-700 mb-2">
                    Name *
                  </label>
                  <input
                    id="groupName"
                    type="text"
                    value={createForm().name}
                    onInput={(e) => setCreateForm({ ...createForm(), name: e.currentTarget.value })}
                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter group name"
                    required
                  />
                </div>
                <div class="mb-4">
                  <label for="groupDescription" class="block text-sm font-medium text-gray-700 mb-2">
                    Description
                  </label>
                  <textarea
                    id="groupDescription"
                    value={createForm().description}
                    onInput={(e) => setCreateForm({ ...createForm(), description: e.currentTarget.value })}
                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter group description (optional)"
                    rows="3"
                  />
                </div>
                <div class="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowCreateModal(false);
                      setCreateForm({ name: '', description: '' });
                      setError(null);
                    }}
                    class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    disabled={creating()}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                    disabled={creating()}
                  >
                    {creating() ? 'Creating...' : 'Create Group'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default Groups;
