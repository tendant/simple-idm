import { Component, createSignal, createEffect, For } from 'solid-js';
import { useNavigate, useSearchParams, A } from '@solidjs/router';
import { twoFactorApi, TwoFactorMethod } from '../api/twoFactor';

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
      // Always use the fixed email for now as per requirements
      await twoFactorApi.sendCode(tempToken(), {
        twofa_type: selectedMethod()?.type,
        email: "aadmin225@example.com"
      });

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
      await twoFactorApi.verifyCode(tempToken(), {
        twofa_type: selectedMethod()?.type,
        passcode: verificationCode()
      });
      
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
              <div>
                <label
                  for="method"
                  class="block text-sm font-medium text-gray-11"
                >
                  Verification Method
                </label>
                <div class="mt-1">
                  <select
                    id="method"
                    name="method"
                    value={selectedMethod()?.type || ''}
                    onChange={(e) => {
                      const method = methods().find(m => m.type === e.currentTarget.value);
                      setSelectedMethod(method || null);
                      setCodeSent(false);
                    }}
                    class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                  >
                    <For each={methods()}>
                      {(method) => (
                        <option value={method.type}>
                          {method.type.charAt(0).toUpperCase() + method.type.slice(1)}
                        </option>
                      )}
                    </For>
                  </select>
                </div>
              </div>

              {selectedMethod() && selectedMethod()?.delivery_options.length > 0 && (
                <div>
                  <label
                    for="delivery-option"
                    class="block text-sm font-medium text-gray-11"
                  >
                    Delivery Option
                  </label>
                  <div class="mt-1">
                    <select
                      id="delivery-option"
                      name="delivery-option"
                      value={selectedDeliveryOption()}
                      onChange={(e) => {
                        setSelectedDeliveryOption(e.currentTarget.value);
                        setCodeSent(false);
                      }}
                      class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                    >
                      <For each={selectedMethod()?.delivery_options}>
                        {(option) => (
                          <option value={option}>{option}</option>
                        )}
                      </For>
                    </select>
                  </div>
                  <div class="mt-1 text-sm text-gray-10">
                    Note: For this demo, verification code will be sent to aadmin225@example.com
                  </div>
                </div>
              )}

              {codeSent() && (
                <div>
                  <label
                    for="code"
                    class="block text-sm font-medium text-gray-11"
                  >
                    Verification Code
                  </label>
                  <div class="mt-1">
                    <input
                      id="code"
                      name="code"
                      type="text"
                      autocomplete="one-time-code"
                      required
                      value={verificationCode()}
                      onInput={(e) => setVerificationCode(e.currentTarget.value)}
                      class="appearance-none block w-full px-3 py-2 border border-gray-7 rounded-lg shadow-sm placeholder:text-gray-8 focus:outline-none focus:ring-2 focus:ring-primary-7 focus:border-primary-7"
                      placeholder="Enter verification code"
                    />
                  </div>
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
                {codeSent() && (
                  <button
                    type="submit"
                    disabled={loading() || !verificationCode()}
                    class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading() ? 'Verifying...' : 'Verify'}
                  </button>
                )}
                
                <button
                  type="button"
                  onClick={sendVerificationCode}
                  disabled={sendingCode() || !selectedMethod()}
                  class="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-lg shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {sendingCode() ? 'Sending...' : codeSent() ? 'Resend Code' : 'Send Verification Code'}
                </button>
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
