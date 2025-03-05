import { Component, createSignal, createEffect, onMount } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { roleApi, type Role } from '../api/role';

const Roles: Component = () => {
  const navigate = useNavigate();
  const [roles, setRoles] = createSignal<Role[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [permissionError, setPermissionError] = createSignal<boolean>(false);
  const [loading, setLoading] = createSignal(true);

  const fetchRoles = async () => {
    try {
      const data = await roleApi.listRoles();
      setRoles(data);
    } catch (err) {
      if (err instanceof Error && err.message === 'No permission') {
        setPermissionError(true);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to fetch roles');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this role?')) return;
    
    try {
      await roleApi.deleteRole(id);
      setRoles(roles().filter(role => role.id !== id));
    } catch (err) {
      if (err instanceof Error && err.message === 'No permission') {
        setPermissionError(true);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to delete role');
      }
    }
  };

  onMount(fetchRoles);

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">Roles</h1>
          <p class="mt-2 text-sm text-gray-11">
            A list of all roles in the system.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            type="button"
            onClick={() => navigate('/roles/create')}
            class="inline-flex items-center justify-center rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            Add Role
          </button>
        </div>
      </div>

      {permissionError() && (
        <div class="mt-4 bg-blue-50 p-4 rounded-lg">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2h-1V9a1 1 0 00-1-1z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-blue-800">No permission</h3>
            </div>
          </div>
        </div>
      )}

      {error() && (
        <div class="mt-4 rounded-lg bg-red-50 p-4">
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

      {!permissionError() && (
        <div class="mt-8 flow-root">
          <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
            <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
              <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-6">
                  <thead class="bg-gray-3">
                    <tr>
                      <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-12 sm:pl-6">
                        Name
                      </th>
                      <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                        <span class="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-gray-6 bg-white">
                    {loading() ? (
                      <tr>
                        <td colSpan={2} class="py-4 pl-4 pr-3 text-sm text-gray-11 sm:pl-6">
                          Loading...
                        </td>
                      </tr>
                    ) : roles().length === 0 ? (
                      <tr>
                        <td colSpan={2} class="py-4 pl-4 pr-3 text-sm text-gray-11 sm:pl-6">
                          No roles found.
                        </td>
                      </tr>
                    ) : (
                      roles().map((role) => (
                        <tr key={role.id}>
                          <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-12 sm:pl-6">
                            {role.name}
                          </td>
                          <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                            <button
                              onClick={() => {
                                console.log('Edit button clicked for role:', role);
                                if (role.id) {
                                  console.log('Navigating to:', `/roles/${role.id}/edit`);
                                  navigate(`/roles/${role.id}/edit`);
                                } else {
                                  console.error('No role ID available');
                                }
                              }}
                              class="text-blue-600 hover:text-blue-900 mr-4"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => role.id && handleDelete(role.id)}
                              class="text-red-600 hover:text-red-900"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Roles;
