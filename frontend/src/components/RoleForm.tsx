import { Component, createSignal } from 'solid-js';
import type { Role } from '../api/role';

interface Props {
  initialData?: Role;
  onSubmit: (data: {
    name: string;
  }) => Promise<void>;
  submitLabel: string;
}

const RoleForm: Component<Props> = (props) => {
  const [name, setName] = createSignal(props.initialData?.name || '');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await props.onSubmit({
        name: name(),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save role');
    } finally {
      setLoading(false);
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
        <label for="name" class="block text-sm font-medium text-gray-11">
          Role Name
        </label>
        <div class="mt-1">
          <input
            type="text"
            name="name"
            id="name"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            class="block w-full appearance-none rounded-lg border border-gray-7 px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>

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

export default RoleForm;
