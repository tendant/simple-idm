import { Component, createResource, ErrorBoundary, Show, Suspense } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import GroupForm from '../components/GroupForm';
import { groupsApi, type Group } from '../api/groups';

const EditGroup: Component = () => {
  const params = useParams();
  const navigate = useNavigate();
  
  const [group] = createResource<Group>(() => {
    if (!params.id) throw new Error('No group ID provided');
    return groupsApi.getGroup(params.id);
  });

  const handleSubmit = async (data: { name: string; description?: string }) => {
    if (!params.id) throw new Error('No group ID provided');
    
    console.log('Submitting group update with ID:', params.id);
    console.log('Update data:', data);
    
    try {
      const updatedGroup = await groupsApi.updateGroup(params.id, data);
      console.log('Group updated successfully:', updatedGroup);
      navigate('/groups');
    } catch (error) {
      console.error('Failed to update group:', error);
      throw error;
    }
  };

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">Edit Group</h1>
          <p class="mt-2 text-sm text-gray-11">
            Edit an existing group in the system.
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
            when={!group.loading && group()} 
            fallback={<div class="text-center">Loading group data...</div>}
          >
            <GroupForm
              onSubmit={handleSubmit}
              submitLabel="Update Group"
              initialData={group()}
            />
          </Show>
        </ErrorBoundary>
      </div>
    </div>
  );
};

export default EditGroup;
