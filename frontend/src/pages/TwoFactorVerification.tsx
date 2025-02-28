import { Component, createSignal, createEffect, For } from 'solid-js';
import { useNavigate, useSearchParams, A } from '@solidjs/router';
import { twoFactorApi, TwoFactorMethod, TwoFactorSendRequest } from '../api/twoFactor';
import { userApi } from '../api/user';

interface TwoFactorVerificationProps {
  tempToken?: string;
  methods?: TwoFactorMethod[];
}

const TwoFactorVerification: Component<TwoFactorVerificationProps> = (props) => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  
  const [tempToken, setTempToken] = createSignal(props.tempToken || searchParams.token || '');
  const [methods, setMethods] = createSignal<TwoFactorMethod[]>(props.methods || []);
  const [selectedMethod, setSelectedMethod] = createSignal<TwoFactorMethod | null>(null);
  const [selectedDeliveryOption, setSelectedDeliveryOption] = createSignal<string>('');
  const [verificationCode, setVerificationCode] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [sendingCode, setSendingCode] = createSignal(false);
  const [codeSent, setCodeSent] = createSignal(false);

  // If methods are not provided via props, try to parse from URL state
  createEffect(() => {
    if (methods().length === 0 && searchParams.methods) {
      try {
        const parsedMethods = JSON.parse(decodeURIComponent(searchParams.methods));
        setMethods(parsedMethods);
        if (parsedMethods.length > 0) {
          setSelectedMethod(parsedMethods[0]);
          if (parsedMethods[0].delivery_options.length > 0) {
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
    if (method && method.delivery_options.length > 0) {
      // If current selection is not in the new method's options, reset it
      if (!method.delivery_options.includes(selectedDeliveryOption())) {
        setSelectedDeliveryOption(method.delivery_options[0]);
      }
    }
  });

  const sendVerificationCode = async () => {
    if (!selectedMethod()) return;
    
    setSendingCode(true);
    setError(null);
    
    try {
      // If the method type is "202", use the login API
      if (selectedMethod()?.type === "202") {
        // For the 202 response type, we need to use the login API
        // with the delivery option as the verification method
        await userApi.login({
          username: "aadmin225@example.com", // Using fixed email as per requirements
          password: selectedDeliveryOption() // Using the delivery option as the verification method
        });
      } else {
        // For other method types, use the twofa API
        const request: TwoFactorSendRequest = {
          twofa_type: selectedMethod()?.type,
          delivery_option: selectedDeliveryOption()
        };
        
        await twoFactorApi.sendCode(tempToken(), request);
      }

      setCodeSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setSendingCode(false);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (selectedMethod()?.type === "202") {
        // For the 202 response type, we need to use the login API
        // with the delivery option as the verification method and passcode
        await userApi.login({
          username: "aadmin225@example.com", // Using fixed email as per requirements
          password: verificationCode() // Using the passcode as the password
        });
      } else {
        // For other method types, use the twofa API
        await twoFactorApi.verifyCode(tempToken(), {
          twofa_type: selectedMethod()?.type,
          passcode: verificationCode()
        });
      }
      
      // Redirect to the users list page
      navigate('/users');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="min-h-screen bg-gray-1 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-12">
          Two-Factor Authentication
        </h2>
        <p class="mt-2 text-center text-sm text-gray-10">
          Please verify your identity using one of the available methods.
        </p>
      </div>

      <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow-lg rounded-lg sm:px-10">
          {methods().length === 0 ? (
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

              {selectedMethod() && selectedMethod().delivery_options.length > 0 && (
                <div class="mb-4">
                  <label
                    class="block text-sm font-medium text-gray-11 mb-2"
                  >
                    {selectedMethod().type === 'email' ? 'Email Address' : 'Delivery Option'}
                  </label>
                  <div class="space-y-2">
                    <For each={selectedMethod().delivery_options}>
                      {(option) => (
                        <div class="flex items-center">
                          <input
                            type="radio"
                            id={`option-${option}`}
                            name="delivery-option"
                            value={option}
                            checked={selectedDeliveryOption() === option}
                            onChange={() => {
                              setSelectedDeliveryOption(option);
                              setCodeSent(false);
                            }}
                            class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                          />
                          <label
                            for={`option-${option}`}
                            class="ml-3 block text-sm font-medium text-gray-11"
                          >
                            {option}
                          </label>
                        </div>
                      )}
                    </For>
                  </div>
                  {selectedMethod().type === 'email' && (
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
                  {codeSent() ? "Code Sent" : selectedMethod()?.type === 'email' ? "Send Code to Email" : "Send Verification Code"}
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
          )}
        </div>
      </div>
    </div>
  );
};

export default TwoFactorVerification;
