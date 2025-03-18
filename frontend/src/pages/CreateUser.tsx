import { Component, createSignal, Show } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { userApi } from '../api/user';
import { loginApi } from '../api/login';
import UserForm from '../components/UserForm';

const CreateUser: Component = () => {
  const navigate = useNavigate();
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [success, setSuccess] = createSignal(false);
  const [createdUser, setCreatedUser] = createSignal<string | null>(null);

  const handleSubmit = async (data: { 
    username?: string; 
    email?: string; 
    password?: string; 
    name?: string;
    role_ids?: string[];
  }) => {
    setLoading(true);
    setError(null);
    setSuccess(false);
    setCreatedUser(null);
    
    try {
      // First create the login if we have a password
      let loginId = null;
      try {
        if (data.password) {
          const newLogin = await loginApi.createLogin({
            username: data.username!,
            email: data.email,
            password: data.password,
          });
          loginId = newLogin.id;
        }
      } catch (loginErr) {
        // If login creation fails, throw a more specific error
        const errorMsg = loginErr instanceof Error ? loginErr.message : 'Failed to create login';
        throw new Error(`Login creation failed: ${errorMsg}`);
      }
      
      // Then create the user with the login ID if available
      try {
        const newUser = await userApi.createUser({
          username: data.username!,
          email: data.email!,
          name: data.name,
          role_ids: data.role_ids,
          login_id: loginId,
          password: data.password || '',
        });
        
        // Set success state and store created username
        setSuccess(true);
        setCreatedUser(newUser.username || data.username || 'new user');
        
        // Redirect after a short delay to show success message
        setTimeout(() => {
          navigate('/users');
        }, 2000);
      } catch (userErr) {
        // If user creation fails but login was created, we should handle this case
        // Ideally, we would delete the login that was created, but for now we'll just show an error
        if (loginId) {
          throw new Error(`User creation failed but login was created. Error: ${userErr instanceof Error ? userErr.message : 'Unknown error'}`);
        }
        throw userErr;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user and login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
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

      {/* Error message */}
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
              <div class="mt-2 text-sm text-red-700">
                <p>Please correct the errors and try again.</p>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Success message */}
      <Show when={success()}>
        <div class="mt-4 rounded-lg bg-green-50 p-4">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-green-800">User created successfully</h3>
              <div class="mt-2 text-sm text-green-700">
                <p>User {createdUser()} has been created. Redirecting to users list...</p>
              </div>
            </div>
          </div>
        </div>
      </Show>

      <div class="mt-8 max-w-xl">
        <UserForm 
          onSubmit={handleSubmit} 
          submitLabel={loading() ? "Creating..." : "Create User"} 
          loading={loading() || success()}
        />
        
        <div class="mt-6 text-sm text-gray-9">
          <p>* Required fields</p>
          <p class="mt-2">Note: Creating a user will also create an associated login if a password is provided.</p>
        </div>
      </div>
    </div>
  );
};

export default CreateUser;
