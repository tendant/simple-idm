import { Component, createSignal, createEffect, For, Show } from 'solid-js';
import { useNavigate, useSearchParams, A, RouteSectionProps } from '@solidjs/router';
import { twoFactorApi, TwoFactorMethod, TwoFactorSendRequest, DeliveryOption, User, SelectUserRequiredResponse } from '../api/twoFactor';
import { userApi } from '../api/user';

interface TwoFactorVerificationProps extends RouteSectionProps {
  tempToken?: string;
  methods?: TwoFactorMethod[];
}

const TwoFactorVerification: Component<TwoFactorVerificationProps> = (props) => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  
  // Handle both string and string[] cases for token
  const tokenParam = searchParams.token 
    ? (Array.isArray(searchParams.token) ? searchParams.token[0] : searchParams.token) 
    : '';
  
  const [tempToken, setTempToken] = createSignal(props.tempToken || tokenParam);
  const [methods, setMethods] = createSignal<TwoFactorMethod[]>(props.methods || []);
  const [selectedMethod, setSelectedMethod] = createSignal<TwoFactorMethod | null>(null);
  const [selectedDeliveryOption, setSelectedDeliveryOption] = createSignal<DeliveryOption | null>(null);
  const [verificationCode, setVerificationCode] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [sendingCode, setSendingCode] = createSignal(false);
  const [codeSent, setCodeSent] = createSignal(false);
  const [userSelectionRequired, setUserSelectionRequired] = createSignal(false);
  const [availableUsers, setAvailableUsers] = createSignal<User[]>([]);
  const [selectedUserId, setSelectedUserId] = createSignal<string | null>(null);
  const [switchingUser, setSwitchingUser] = createSignal(false);

  // Check if user selection is required from URL parameters
  createEffect(() => {
    const userSelectionRequiredParam = searchParams.user_selection_required;
    if (userSelectionRequiredParam === 'true') {
      setUserSelectionRequired(true);
      
      // Parse users from URL parameters
      if (searchParams.users) {
        try {
          // Handle both string and string[] cases
          const usersParam = Array.isArray(searchParams.users) 
            ? searchParams.users[0] 
            : searchParams.users;
          
          const parsedUsers = JSON.parse(decodeURIComponent(usersParam));
          setAvailableUsers(parsedUsers);
          
          // If there's only one user, select it automatically
          if (parsedUsers.length === 1) {
            setSelectedUserId(parsedUsers[0].id);
          }
        } catch (err) {
          console.error('Failed to parse users from URL', err);
          setError('Failed to load user accounts');
        }
      }
    }
  });

  // If methods are not provided via props, try to parse from URL state
  createEffect(() => {
    if (methods().length === 0 && searchParams.methods) {
      try {
        // Handle both string and string[] cases
        const methodsParam = Array.isArray(searchParams.methods) 
          ? searchParams.methods[0] 
          : searchParams.methods;
        
        const parsedMethods = JSON.parse(decodeURIComponent(methodsParam));
        setMethods(parsedMethods);
        if (parsedMethods.length > 0) {
          setSelectedMethod(parsedMethods[0]);
          if (parsedMethods[0].delivery_options && parsedMethods[0].delivery_options.length > 0) {
            setSelectedDeliveryOption(parsedMethods[0].delivery_options[0]);
          }
        }
      } catch (err) {
        console.error('Failed to parse 2FA methods from URL', err);
      }
    }
  });

  // Update selected delivery option when method changes
  createEffect(() => {
    const method = selectedMethod();
    if (method && method.delivery_options && method.delivery_options.length > 0) {
      // If current selection is not in the new method's options, reset it
      const currentOption = selectedDeliveryOption();
      if (!currentOption || !method.delivery_options.some(option => option.hashed_value === currentOption.hashed_value)) {
        setSelectedDeliveryOption(method.delivery_options[0]);
      }
    }
  });

  const sendVerificationCode = async () => {
    const method = selectedMethod();
    if (!method) return;
    
    setSendingCode(true);
    setError(null);
    
    try {
      // If the method type is "202", use the login API
      if (method.type === "202") {
        // For the 202 response type, we need to use the login API
        // with the delivery option as the verification method
        const option = selectedDeliveryOption();
        if (!option) {
          throw new Error("No delivery option selected");
        }
        
        await userApi.login({
          username: "aadmin225@example.com", // Using fixed email as per requirements
          password: option.hashed_value // Using the hashed_value of the delivery option as the verification method
        });
      } else {
        // For other method types, use the twofa API
        const option = selectedDeliveryOption();
        if (!option) {
          throw new Error("No delivery option selected");
        }
        
        const request: TwoFactorSendRequest = {
          twofa_type: method.type,
          delivery_option: option.hashed_value
        };
        
        const token = tempToken();
        if (!token) {
          throw new Error("No token available");
        }
        
        await twoFactorApi.sendCode(token, request);
      }

      setCodeSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setSendingCode(false);
    }
  };

  // This function handles user selection and switching to the selected user account
  const handleUserSelection = async () => {
    if (!selectedUserId()) {
      setError('Please select a user account');
      return;
    }
    
    setSwitchingUser(true);
    setError(null);
    
    try {
      // Call the switchUser API with the selected user ID and temp token
      const response = await userApi.switchUser(selectedUserId()!, tempToken());
      
      // Store the user info in localStorage
      localStorage.setItem('user', JSON.stringify(response));
      
      // Redirect to the original page or default to /users
      let redirectPath = '/users';
      if (searchParams.redirect) {
        redirectPath = Array.isArray(searchParams.redirect) 
          ? searchParams.redirect[0] 
          : searchParams.redirect;
      }
      navigate(redirectPath);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch user');
      setSwitchingUser(false);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const method = selectedMethod();
    if (!method) {
      setError("No verification method selected");
      setLoading(false);
      return;
    }

    try {
      if (method.type === "202") {
        // For the 202 response type, we need to use the login API
        // with the delivery option as the verification method and passcode
        await userApi.login({
          username: "aadmin225@example.com", // Using fixed email as per requirements
          password: verificationCode() // Using the passcode as the password
        });
      } else {
        // For other method types, use the twofa API
        const token = tempToken();
        if (!token) {
          throw new Error("No token available");
        }
        
        const response = await twoFactorApi.verifyCode(token, {
          twofa_type: method.type,
          passcode: verificationCode()
        });

        // Check if user selection is required
        if (response.status === 'select_user_required') {
          setTempToken(response.temp_token);
          setAvailableUsers(response.users);
          setUserSelectionRequired(true);
          setSelectedUserId(response.users.length > 0 ? response.users[0].id : null);
          return;
        }
      }
      
      // Redirect to the users list page
      navigate('/users');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  // The handleUserSelection function is already defined above

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          {userSelectionRequired() ? 'Select User Account' : 'Two-Factor Authentication'}
        </h2>
        <p class="mt-2 text-center text-sm text-gray-10">
          {userSelectionRequired() 
            ? 'Multiple user accounts found. Please select which account you want to access.'
            : 'Please verify your identity using one of the available methods.'}
        </p>
      </div>

      <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow-lg rounded-lg sm:px-10">
          <Show
            when={userSelectionRequired()}
            fallback={
              methods().length === 0 ? (
                <div class="text-center text-gray-11">
                  <p>No two-factor authentication methods available.</p>
                  <div class="mt-4">
                    <A
                      href="/login"
                      class="text-sm text-blue-600 hover:text-blue-500"
                    >
                      Return to login
                    </A>
                  </div>
                </div>
              ) : (
                <form class="space-y-6" onSubmit={handleSubmit}>
                  <div class="mb-4">
                    <label
                      class="block text-sm font-medium text-gray-11 mb-2"
                    >
                      Verification Method
                    </label>
                    <div class="space-y-2">
                      <For each={methods()}>
                        {(method) => (
                          <div class="flex items-center">
                            <input
                              type="radio"
                              id={`method-${method.type}`}
                              name="verification-method"
                              value={method.type}
                              checked={selectedMethod()?.type === method.type}
                              onChange={() => {
                                setSelectedMethod(method);
                                if (method.delivery_options.length > 0) {
                                  setSelectedDeliveryOption(method.delivery_options[0]);
                                }
                                setCodeSent(false);
                              }}
                              class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                            />
                            <label
                              for={`method-${method.type}`}
                              class="ml-3 block text-sm font-medium text-gray-11"
                            >
                              {method.display_name || method.type}
                            </label>
                          </div>
                        )}
                      </For>
                    </div>
                  </div>

                  {selectedMethod() && selectedMethod()!.delivery_options.length > 0 && (
                    <div class="mb-4">
                      <label
                        class="block text-sm font-medium text-gray-11 mb-2"
                      >
                        {selectedMethod()!.type === 'email' ? 'Email Address' : 'Delivery Option'}
                      </label>
                      <div class="space-y-2">
                        <For each={selectedMethod()!.delivery_options}>
                          {(option) => (
                            <div class="flex items-center">
                              <input
                                type="radio"
                                id={`option-${option.hashed_value}`}
                                name="delivery-option"
                                value={option.hashed_value}
                                checked={selectedDeliveryOption()?.hashed_value === option.hashed_value}
                                onChange={() => {
                                  setSelectedDeliveryOption(option);
                                  setCodeSent(false);
                                }}
                                class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                              />
                              <label
                                for={`option-${option.hashed_value}`}
                                class="ml-3 block text-sm font-medium text-gray-11"
                              >
                                {option.display_value}
                              </label>
                            </div>
                          )}
                        </For>
                      </div>
                      {selectedMethod()!.type === 'email' && (
                        <div class="mt-2 text-sm text-gray-10">
                          Verification code will be sent to the selected email address.
                        </div>
                      )}
                    </div>
                  )}

                  {codeSent() && (
                    <div class="mb-4">
                      <label
                        for="verification-code"
                        class="block text-sm font-medium text-gray-11 mb-2"
                      >
                        Verification Code
                      </label>
                      <input
                        id="verification-code"
                        name="verification-code"
                        type="text"
                        autocomplete="one-time-code"
                        required
                        placeholder="Enter the code sent to you"
                        value={verificationCode()}
                        onInput={(e) => setVerificationCode(e.currentTarget.value)}
                        class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-center text-lg tracking-wider"
                        maxlength="6"
                      />
                    </div>
                  )}
                  
                  {!codeSent() && selectedMethod() && (
                    <div class="mb-4 text-sm text-gray-10">
                      Click "{selectedMethod()?.type === 'email' ? 'Send Code to Email' : 'Send Verification Code'}" to receive your verification code
                    </div>
                  )}

                  {error() && (
                    <div class="rounded-lg bg-red-2 p-4">
                      <div class="flex">
                        <div class="ml-3">
                          <h3 class="text-sm font-medium text-red-11">{error()}</h3>
                        </div>
                      </div>
                    </div>
                  )}

                  <div class="flex flex-col space-y-4">
                    <button
                      type="button"
                      onClick={sendVerificationCode}
                      disabled={!selectedMethod() || codeSent() || sendingCode()}
                      class="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-lg shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {codeSent() ? "Code Sent" : (selectedMethod() && selectedMethod()!.type === 'email') ? "Send Code to Email" : "Send Verification Code"}
                    </button>

                    {codeSent() && (
                      <button
                        type="submit"
                        disabled={loading() || !verificationCode()}
                        class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {loading() ? "Verifying..." : "Verify Code & Continue"}
                      </button>
                    )}
                  </div>

                  <div class="text-center">
                    <A
                      href="/login"
                      class="text-sm text-blue-600 hover:text-blue-500"
                    >
                      Return to login
                    </A>
                  </div>
                </form>
              )
            }
          >
            <div class="space-y-6">
              <div class="mb-4">
                <label class="block text-sm font-medium text-gray-11 mb-2">
                  Select User Account
                </label>
                <div class="space-y-2">
                  <For each={availableUsers()}>
                    {(user) => (
                      <div class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer"
                           classList={{
                             'border-blue-500 bg-blue-50': selectedUserId() === user.id,
                             'border-gray-200': selectedUserId() !== user.id
                           }}
                           onClick={() => setSelectedUserId(user.id)}>
                        <input
                          type="radio"
                          id={`user-${user.id}`}
                          name="user-selection"
                          value={user.id}
                          checked={selectedUserId() === user.id}
                          onChange={() => setSelectedUserId(user.id)}
                          class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                        />
                        <div class="ml-3 flex flex-col">
                          <label
                            for={`user-${user.id}`}
                            class="block text-sm font-medium text-gray-11"
                          >
                            {user.name}
                          </label>
                          <span class="text-xs text-gray-9">{user.email}</span>
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </div>

              {error() && (
                <div class="rounded-lg bg-red-2 p-4">
                  <div class="flex">
                    <div class="ml-3">
                      <h3 class="text-sm font-medium text-red-11">{error()}</h3>
                    </div>
                  </div>
                </div>
              )}

              <div class="flex flex-col space-y-4">
                <button
                  type="button"
                  onClick={handleUserSelection}
                  disabled={!selectedUserId() || switchingUser()}
                  class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {switchingUser() ? "Switching..." : "Continue with Selected User"}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setUserSelectionRequired(false);
                    setError(null);
                  }}
                  class="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-lg shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Back to Verification
                </button>
              </div>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
};

export default TwoFactorVerification;
