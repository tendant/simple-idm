import { Component } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import RoleForm from '../components/RoleForm';
import { roleApi } from '../api/role';

const CreateRole: Component = () => {
  const navigate = useNavigate();

  const handleSubmit = async (data: { name: string }) => {
    await roleApi.createRole(data);
    navigate('/roles');
  };

  return (
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-12">Create Role</h1>
          <p class="mt-2 text-sm text-gray-11">
            Create a new role in the system.
          </p>
        </div>
      </div>

      <div class="mt-8">
        <RoleForm onSubmit={handleSubmit} submitLabel="Create Role" />
      </div>
    </div>
  );
};

export default CreateRole;
