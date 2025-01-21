import { Component, createSignal, onMount, Show } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import { userApi } from '../api/user';
import UserForm from '../components/UserForm';
import type { User } from '../api/user';

const EditUser: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  const [user, setUser] = createSignal<User | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  onMount(async () => {
    try {
      const data = await userApi.getUser(params.id);
      setUser(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch user');
      if (err instanceof Error && err.message === 'Authentication expired. Please log in again.') {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  });

  const handleSubmit = async (data: { 
    username?: string; 
    email?: string; 
    password?: string; 
    name?: string;
    role_uuids?: string[];
  }) => {
    await userApi.updateUser(params.id, {
      username: data.username,
      password: data.password,
      name: data.name,
      role_uuids: data.role_uuids,
    });
    navigate('/users');
  };

  return (
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-11 sm:truncate sm:text-3xl sm:tracking-tight">
            Edit User
          </h2>
        </div>
        <div class="mt-4 flex md:mt-0 md:ml-4">
          <button
            type="button"
            onClick={() => navigate('/users')}
            class="inline-flex items-center rounded-lg border border-gray-7 bg-white px-4 py-2 text-sm font-medium text-gray-11 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            Cancel
          </button>
        </div>
      </div>

      <div class="mt-8 max-w-xl">
        <Show
          when={!loading()}
          fallback={<div class="text-center">Loading...</div>}
        >
          <Show
            when={user()}
            fallback={
              <div class="rounded-lg bg-red-50 p-4">
                <div class="flex">
                  <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                    </svg>
                  </div>
                  <div class="ml-3">
                    <h3 class="text-sm font-medium text-red-800">{error() || 'User not found'}</h3>
                  </div>
                </div>
              </div>
            }
          >
            <UserForm
              initialData={user()!}
              onSubmit={handleSubmit}
              submitLabel="Save Changes"
            />
          </Show>
        </Show>
      </div>
    </div>
  );
};

export default EditUser;
