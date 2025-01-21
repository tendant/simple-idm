import { Component } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { userApi } from '../api/user';
import UserForm from '../components/UserForm';

const CreateUser: Component = () => {
  const navigate = useNavigate();

  const handleSubmit = async (data: { username?: string; password?: string; name?: string }) => {
    await userApi.createUser({
      username: data.username!,
      password: data.password!,
      name: data.name,
    });
    navigate('/users');
  };

  return (
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-11 sm:truncate sm:text-3xl sm:tracking-tight">
            Create New User
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
        <UserForm onSubmit={handleSubmit} submitLabel="Create User" />
      </div>
    </div>
  );
};

export default CreateUser;
