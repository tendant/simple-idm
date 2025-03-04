import { Component, createSignal, createResource, For, Show } from 'solid-js';
import type { User } from '../api/user';
import { roleApi, type Role } from '../api/role';
import { loginApi, type Login } from '../api/login';

interface Props {
  initialData?: User;
  onSubmit: (data: {
    username?: string;
    email?: string;
    password?: string;
    name?: string;
    role_ids?: string[];
    login_id?: string;
  }) => Promise<void>;
  submitLabel: string;
}

const UserForm: Component<Props> = (props) => {
  const [username, setUsername] = createSignal(props.initialData?.username || '');
  const [email, setEmail] = createSignal(props.initialData?.email || '');
  const [password, setPassword] = createSignal('');
  const [name, setName] = createSignal(props.initialData?.name || '');
  const [selectedRoles, setSelectedRoles] = createSignal<string[]>(
    props.initialData?.roles?.map(r => r.id || '').filter(id => id !== '') || []
  );
  const [selectedLogin, setSelectedLogin] = createSignal<string>(props.initialData?.login_id || '');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  // Fetch available roles
  const [roles] = createResource<Role[]>(async () => {
    try {
      return await roleApi.listRoles();
    } catch (err) {
      console.error('Failed to fetch roles:', err);
      return [];
    }
  });

  // Fetch available logins
  const [logins] = createResource<Login[]>(async () => {
    try {
      return await loginApi.listLogins();
    } catch (err) {
      console.error('Failed to fetch logins:', err);
      return [];
    }
  });

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await props.onSubmit({
        username: username(),
        email: email(),
        password: password() || undefined,
        name: name() || undefined,
        role_ids: selectedRoles().filter(id => id !== ''),
        login_id: selectedLogin() || undefined,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save user');
    } finally {
      setLoading(false);
    }
  };

  const toggleRole = (roleUuid: string) => {
    if (!roleUuid) return; // Skip empty UUIDs
    const current = selectedRoles();
    if (current.includes(roleUuid)) {
      setSelectedRoles(current.filter(id => id !== roleUuid));
    } else {
      setSelectedRoles([...current, roleUuid]);
    }
  };

  return (
    <form onSubmit={handleSubmit} class="space-y-6">
      {error() && (
        <div class="rounded-lg bg-red-50 p-4">
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

      <div>
        <label for="username" class="block text-sm font-medium text-gray-11">
          Username
        </label>
        <div class="mt-1">
          <input
            type="text"
            name="username"
            id="username"
            required
            value={username()}
            onInput={(e) => setUsername(e.currentTarget.value)}
            class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            disabled={!!props.initialData}
          />
        </div>
      </div>

      <div>
        <label for="email" class="block text-sm font-medium text-gray-11">
          Email
        </label>
        <div class="mt-1">
          <input
            type="email"
            name="email"
            id="email"
            required
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
            class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            disabled={!!props.initialData}
          />
        </div>
      </div>

      <div>
        <label for="name" class="block text-sm font-medium text-gray-11">
          Full Name
        </label>
        <div class="mt-1">
          <input
            type="text"
            name="name"
            id="name"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>

      {!props.initialData && (
        <div>
          <label for="password" class="block text-sm font-medium text-gray-11">
            Password
          </label>
          <div class="mt-1">
            <input
              type="password"
              name="password"
              id="password"
              required
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
              class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>
      )}

      <div>
        <label class="block text-sm font-medium text-gray-11">
          Roles
        </label>
        <div class="mt-2 space-y-2">
          <For each={roles()}>
            {(role) => (
              <div class="flex items-center">
                <input
                  type="checkbox"
                  id={`role-${role.uuid}`}
                  checked={selectedRoles().includes(role.uuid || '')}
                  onChange={() => role.uuid && toggleRole(role.uuid)}
                  class="h-4 w-4 rounded border-gray-7 text-blue-600 focus:ring-blue-500"
                />
                <label
                  for={`role-${role.uuid}`}
                  class="ml-2 text-sm text-gray-11"
                >
                  {role.name}
                </label>
              </div>
            )}
          </For>
        </div>
      </div>

      <Show when={props.initialData}>
        <div>
          <label class="block text-sm font-medium text-gray-11">
            Associated Login
          </label>
          <div class="mt-1">
            <select
              value={selectedLogin()}
              onChange={(e) => setSelectedLogin(e.currentTarget.value)}
              class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">None</option>
              <For each={logins()}>
                {(login) => (
                  <option value={login.id}>
                    {login.username} ({login.email || 'No email'})
                  </option>
                )}
              </For>
            </select>
          </div>
          <p class="mt-1 text-sm text-gray-9">
            Select a login to associate with this user
          </p>
        </div>
      </Show>

      <div>
        <button
          type="submit"
          disabled={loading()}
          class="w-full rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 disabled:opacity-50"
        >
          {loading() ? 'Loading...' : props.submitLabel}
        </button>
      </div>
    </form>
  );
};

export default UserForm;
