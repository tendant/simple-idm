import type { Component } from 'solid-js';
import { createEffect, createResource, createSignal, For, Show } from 'solid-js';

import type { Login } from '../api/login';
import { loginApi } from '../api/login';
import type { Role } from '../api/role';
import { roleApi } from '../api/role';
import type { User } from '../api/user';

interface Props {
  initialData?: User
  onSubmit: (data: {
    username?: string
    email?: string
    password?: string
    name?: string
    role_ids?: string[]
    login_id?: string
  }) => Promise<void>
  submitLabel: string
  loading?: boolean
}

const UserForm: Component<Props> = (props) => {
  const [username, setUsername] = createSignal(props.initialData?.username || '');
  const [email, setEmail] = createSignal(props.initialData?.email || '');
  const [password, setPassword] = createSignal('');
  const [name, setName] = createSignal(props.initialData?.name || '');
  const [selectedRoles, setSelectedRoles] = createSignal<string[]>(
    props.initialData?.roles?.map(r => r.id || '').filter(id => id !== '') || props.initialData?.role_ids || [],
  );
  const [selectedLogin, setSelectedLogin] = createSignal<string>(props.initialData?.login_id || '');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(props.loading || false);

  // Field-specific validation errors
  const [usernameError, setUsernameError] = createSignal<string | null>(null);
  const [emailError, setEmailError] = createSignal<string | null>(null);
  const [passwordError, setPasswordError] = createSignal<string | null>(null);

  // Update loading state when props change
  createEffect(() => {
    setLoading(props.loading || false);
  });

  // Fetch available roles
  const [roles] = createResource<Role[]>(async () => {
    try {
      return await roleApi.listRoles();
    }
    catch (err) {
      console.error('Failed to fetch roles:', err);
      return [];
    }
  });

  // Fetch available logins
  const [logins] = createResource<Login[]>(async () => {
    try {
      return await loginApi.listLogins();
    }
    catch (err) {
      console.error('Failed to fetch logins:', err);
      return [];
    }
  });

  // Validate form fields
  const validateForm = () => {
    let isValid = true;

    // Reset all errors
    setUsernameError(null);
    setEmailError(null);
    setPasswordError(null);
    setError(null);

    // Username validation
    if (!username()) {
      setUsernameError('Username is required');
      isValid = false;
    }
    else if (username().length < 3) {
      setUsernameError('Username must be at least 3 characters');
      isValid = false;
    }

    // Email validation
    if (!email()) {
      setEmailError('Email is required');
      isValid = false;
    }
    else if (!/^\S[^\s@]*@\S[^\s.]*\.\S+$/.test(email())) {
      setEmailError('Please enter a valid email address');
      isValid = false;
    }

    // Password validation (only for new users)
    if (!props.initialData && !password()) {
      setPasswordError('Password is required');
      isValid = false;
    }
    else if (!props.initialData && password().length < 8) {
      setPasswordError('Password must be at least 8 characters');
      isValid = false;
    }

    return isValid;
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    // Validate form before submission
    if (!validateForm()) {
      return;
    }

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
    }
    catch (err) {
      const errorMsg = err instanceof Error
        ? err.message
        : 'Failed to save user';

      // Handle field-specific errors
      if (errorMsg.includes('Username error')) {
        setUsernameError(errorMsg.replace('Username error: ', ''));
      }
      else if (errorMsg.includes('Email error')) {
        setEmailError(errorMsg.replace('Email error: ', ''));
      }
      else if (errorMsg.includes('Password error')) {
        setPasswordError(errorMsg.replace('Password error: ', ''));
      }
      else {
        // General error
        setError(errorMsg);
      }
    }
    finally {
      setLoading(false);
    }
  };

  const toggleRole = (roleId: string) => {
    if (!roleId)
      return; // Skip empty IDs
    const current = selectedRoles();
    if (current.includes(roleId)) {
      setSelectedRoles(current.filter(id => id !== roleId));
    }
    else {
      setSelectedRoles([...current, roleId]);
    }
  };

  return (
    <form
      class="space-y-6"
      onSubmit={handleSubmit}
    >
      {error() && (
        <div
          class="rounded-lg bg-red-50 p-4"
        >
          <div
            class="flex"
          >
            <div
              class="flex-shrink-0"
            >
              <svg
                class="h-5 w-5 text-red-400"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  clip-rule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  fill-rule="evenodd"
                />
              </svg>
            </div>
            <div
              class="ml-3"
            >
              <h3
                class="text-sm font-medium text-red-800"
              >
                {error()}
              </h3>
            </div>
          </div>
        </div>
      )}

      <div>
        <label
          class="block text-sm font-medium text-gray-11"
          for="username"
        >
          Username
          {' '}
          <span
            class="text-red-600"
          >
            *
          </span>
        </label>
        <div
          class="mt-1"
        >
          <input
            required
            disabled={!!props.initialData}
            id="username"
            name="username"
            placeholder="Enter username (min 3 characters)"
            type="text"
            value={username()}
            class={`block w-full appearance-none rounded-lg border ${usernameError()
              ? 'border-red-500'
              : 'border-gray-7'} px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500`}
            onInput={(e) => {
              setUsername(e.currentTarget.value);
              setUsernameError(null);
            }}
          />
          {usernameError() && (
            <p
              class="mt-1 text-sm text-red-600"
            >
              {usernameError()}
            </p>
          )}
        </div>
      </div>

      <div>
        <label
          class="block text-sm font-medium text-gray-11"
          for="email"
        >
          Email
          {' '}
          <span
            class="text-red-600"
          >
            *
          </span>
        </label>
        <div
          class="mt-1"
        >
          <input
            required
            disabled={!!props.initialData}
            id="email"
            name="email"
            placeholder="Enter a valid email address"
            type="email"
            value={email()}
            class={`block w-full appearance-none rounded-lg border ${emailError()
              ? 'border-red-500'
              : 'border-gray-7'} px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500`}
            onInput={(e) => {
              setEmail(e.currentTarget.value);
              setEmailError(null);
            }}
          />
          {emailError() && (
            <p
              class="mt-1 text-sm text-red-600"
            >
              {emailError()}
            </p>
          )}
        </div>
      </div>

      <div>
        <label
          class="block text-sm font-medium text-gray-11"
          for="name"
        >
          Full Name
        </label>
        <div
          class="mt-1"
        >
          <input
            class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            id="name"
            name="name"
            type="text"
            value={name()}
            onInput={e => setName(e.currentTarget.value)}
          />
        </div>
      </div>

      {!props.initialData && (
        <div>
          <label
            class="block text-sm font-medium text-gray-11"
            for="password"
          >
            Password
            {' '}
            <span
              class="text-red-600"
            >
              *
            </span>
          </label>
          <div
            class="mt-1"
          >
            <input
              required
              id="password"
              name="password"
              placeholder="Enter password (min 8 characters)"
              type="password"
              value={password()}
              class={`block w-full appearance-none rounded-lg border ${passwordError()
                ? 'border-red-500'
                : 'border-gray-7'} px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500`}
              onInput={(e) => {
                setPassword(e.currentTarget.value);
                setPasswordError(null);
              }}
            />
            {passwordError() && (
              <p
                class="mt-1 text-sm text-red-600"
              >
                {passwordError()}
              </p>
            )}
          </div>
          <p
            class="mt-1 text-xs text-gray-9"
          >
            Password should be at least 8 characters and include a mix of letters, numbers, and special characters for better security.
          </p>
        </div>
      )}

      <div>
        <label
          class="block text-sm font-medium text-gray-11"
        >
          Roles
        </label>
        <div
          class="mt-2 space-y-2"
        >
          <For
            each={roles()}
          >
            {role => (
              <div
                class="flex items-center"
              >
                <input
                  checked={selectedRoles().includes(role.id || '')}
                  class="h-4 w-4 rounded border-gray-7 text-blue-600 focus:ring-blue-500"
                  id={`role-${role.id}`}
                  type="checkbox"
                  onChange={() => role.id && toggleRole(role.id)}
                />
                <label
                  class="ml-2 text-sm text-gray-11"
                  for={`role-${role.id}`}
                >
                  {role.name}
                </label>
              </div>
            )}
          </For>
        </div>
      </div>

      <Show
        when={props.initialData}
      >
        <div>
          <label
            class="block text-sm font-medium text-gray-11"
          >
            Associated Login
          </label>
          <div
            class="mt-1"
          >
            <select
              class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              value={selectedLogin()}
              onChange={e => setSelectedLogin(e.currentTarget.value)}
            >
              <option
                value=""
              >
                None
              </option>
              <For
                each={logins()}
              >
                {login => (
                  <option
                    selected={login.id === props.initialData?.login_id}
                    value={login.id}
                  >
                    {login.username}
                    {' '}
                    {login.id === props.initialData?.login_id ? '(Current)' : ''}
                  </option>
                )}
              </For>
            </select>
          </div>
          <p
            class="mt-1 text-sm text-gray-9"
          >
            Select a login to associate with this user
          </p>
        </div>
      </Show>

      <div>
        <button
          class="w-full rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 disabled:opacity-50"
          disabled={loading() || props.loading}
          type="submit"
        >
          {loading() || props.loading ? 'Loading...' : props.submitLabel}
        </button>
      </div>
    </form>
  );
};

export default UserForm;
