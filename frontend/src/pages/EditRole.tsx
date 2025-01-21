import { Component, createResource, Show, Suspense, ErrorBoundary } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import RoleForm from '../components/RoleForm';
import { roleApi, type Role } from '../api/role';

const EditRole: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  
  const [role] = createResource<Role>(() => {
    if (!params.uuid) throw new Error('No role UUID provided');
    return roleApi.getRole(params.uuid);
  });

  const handleSubmit = async (data: { name: string }) => {
    if (!params.uuid) throw new Error('No role UUID provided');
    await roleApi.updateRole(params.uuid, data);
    navigate('/roles');
  };

  return (
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">Edit Role</h1>
          <p class="mt-2 text-sm text-gray-11">
            Edit an existing role in the system.
          </p>
        </div>
      </div>

      <div class="mt-8">
        <ErrorBoundary fallback={err => (
          <div class="rounded-lg bg-red-50 p-4">
            <div class="flex">
              <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                </svg>
              </div>
              <div class="ml-3">
                <h3 class="text-sm font-medium text-red-800">{err.message}</h3>
              </div>
            </div>
          </div>
        )}>
          <Show 
            when={!role.loading && role()} 
            fallback={<div class="text-center">Loading role data...</div>}
          >
            <RoleForm
              onSubmit={handleSubmit}
              submitLabel="Update Role"
              initialData={role()}
            />
          </Show>
        </ErrorBoundary>
      </div>
    </div>
  );
};

export default EditRole;
