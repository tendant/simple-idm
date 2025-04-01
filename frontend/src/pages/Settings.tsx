import type { Component } from 'solid-js';
import { createEffect, createSignal, For, Show } from 'solid-js';

import type { ProfileTwoFactorMethod } from '../api/twoFactor';
import { twoFactorApi } from '../api/twoFactor';
import { AssociatedAccounts } from '../components/AssociatedAccounts';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { extractErrorDetails } from '../lib/api';
import { useApi } from '../lib/hooks/useApi';

const Settings: Component = () => {
  const [currentPassword, setCurrentPassword] = createSignal('');
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [twoFactorEnabled, setTwoFactorEnabled] = createSignal(false);
  const [backupCodes, setBackupCodes] = createSignal<string[] | null>(null);
  const [twoFactorCode, setTwoFactorCode] = createSignal('');
  const [twoFactorType, setTwoFactorType] = createSignal<string>('email');
  const [isAddingMethod, setIsAddingMethod] = createSignal(false);
  const [isLoading, setIsLoading] = createSignal(false);
  const [twoFactorMethods, setTwoFactorMethods] = createSignal<ProfileTwoFactorMethod[]>([]);
  const [isLoadingMethods, setIsLoadingMethods] = createSignal(false);

  const { request } = useApi();

  const fetch2FAMethods = async () => {
    setIsLoadingMethods(true);
    try {
      const data = await twoFactorApi.get2FAMethods();
      setTwoFactorMethods(data.methods || []);
      setTwoFactorEnabled(data.methods && data.methods.length > 0);
    }
    catch (err) {
      const errorDetails = extractErrorDetails(err);
      setError(errorDetails.message || 'Failed to fetch 2FA methods');
    }
    finally {
      setIsLoadingMethods(false);
    }
  };

  // Fetch 2FA methods when component mounts
  createEffect(() => {
    fetch2FAMethods();
  });

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword() !== confirmPassword()) {
      setError('New passwords do not match');
      return;
    }

    try {
      await request('/profile/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: currentPassword(),
          new_password: newPassword(),
        }),
      });

      setSuccess('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    }
    catch (err) {
      const errorDetails = extractErrorDetails(err);

      // Handle specific error codes
      if (errorDetails.code === 'invalid_password') {
        setError('Current password is incorrect');
      }
      else if (errorDetails.code === 'invalid_password_complexity') {
        // Display the specific password complexity error message
        setError(errorDetails.message);
      }
      else {
        // For any other error, display the message
        setError(errorDetails.message);
      }
    }
  };

  return (
    <div>
      <div
        class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8"
      >
        <div
          class="container mx-auto p-4"
        >
          <div
            class="mx-auto max-w-2xl"
          >
            <h1
              class="mb-8 text-2xl font-bold"
            >
              User Settings
            </h1>

            {success() && (
              <Alert
                class="mb-4"
              >
                <AlertTitle>Success</AlertTitle>
                <AlertDescription>
                  {success()}
                </AlertDescription>
              </Alert>
            )}

            {error() && (
              <Alert
                class="mb-4"
                variant="destructive"
              >
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>
                  {error()}
                </AlertDescription>
              </Alert>
            )}

            <Tabs
              class="w-full"
              defaultValue="password"
            >
              <TabsList
                class="grid w-full grid-cols-3"
              >
                <TabsTrigger
                  value="password"
                >
                  Password
                </TabsTrigger>
                <TabsTrigger
                  value="2fa"
                >
                  Two-Factor Auth
                </TabsTrigger>
                <TabsTrigger
                  value="accounts"
                >
                  Associated Accounts
                </TabsTrigger>
              </TabsList>

              <TabsContent
                value="password"
              >
                <Card>
                  <CardHeader>
                    <CardTitle>Change Password</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <form
                      class="space-y-4"
                      onSubmit={handleSubmit}
                    >
                      <div
                        class="space-y-2"
                      >
                        <Label
                          for="current-password"
                        >
                          Current Password
                        </Label>
                        <Input
                          required
                          id="current-password"
                          type="password"
                          value={currentPassword()}
                          onInput={e => setCurrentPassword(e.currentTarget.value)}
                        />
                      </div>

                      <div
                        class="space-y-2"
                      >
                        <Label
                          for="new-password"
                        >
                          New Password
                        </Label>
                        <Input
                          required
                          id="new-password"
                          type="password"
                          value={newPassword()}
                          onInput={e => setNewPassword(e.currentTarget.value)}
                        />
                      </div>

                      <div
                        class="space-y-2"
                      >
                        <Label
                          for="confirm-password"
                        >
                          Confirm New Password
                        </Label>
                        <Input
                          required
                          id="confirm-password"
                          type="password"
                          value={confirmPassword()}
                          onInput={e => setConfirmPassword(e.currentTarget.value)}
                        />
                      </div>

                      <Button
                        class="w-full"
                        type="submit"
                      >
                        Change Password
                      </Button>
                    </form>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent
                value="2fa"
              >
                <Card>
                  <CardHeader>
                    <CardTitle>Two-Factor Authentication</CardTitle>
                  </CardHeader>
                  <CardContent>

                    <div
                      class="space-y-4"
                    >
                      <p
                        class="text-sm text-gray-600"
                      >
                        Two-factor authentication adds an extra layer of security to your account.
                        When enabled, you'll need to enter both your password and a verification code
                        when signing in.
                      </p>

                      <Show
                        when={isAddingMethod()}
                      >
                        <div
                          class="space-y-4 p-4 border rounded-md"
                        >
                          <h3
                            class="font-medium"
                          >
                            Add 2FA Method
                          </h3>
                          <div
                            class="space-y-2"
                          >
                            <Label
                              for="twofa-type"
                            >
                              Authentication Type
                            </Label>
                            <div
                              class="relative"
                            >
                              <select
                                class="w-full h-10 rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                                id="twofa-type"
                                value={twoFactorType()}
                                onChange={e => setTwoFactorType(e.target.value)}
                              >
                                <option
                                  value="email"
                                >
                                  Email
                                </option>
                                <option
                                  value="sms"
                                >
                                  SMS
                                </option>
                              </select>
                            </div>
                          </div>

                          <div
                            class="flex space-x-2"
                          >
                            <Button
                              disabled={isLoading()}
                              onClick={async () => {
                                setError(null);
                                setSuccess(null);
                                setIsLoading(true);
                                try {
                                  await twoFactorApi.setup2FAMethod(twoFactorType());
                                  setSuccess(`${twoFactorType().toUpperCase()} 2FA method added successfully`);
                                  setTwoFactorEnabled(true);
                                  setIsAddingMethod(false);
                                  fetch2FAMethods();
                                }
                                catch (err) {
                                  const errorDetails = extractErrorDetails(err);
                                  setError(errorDetails.message || `Failed to setup ${twoFactorType()} 2FA method`);
                                }
                                finally {
                                  setIsLoading(false);
                                }
                              }}
                            >
                              {isLoading() ? 'Adding...' : 'Add Method'}
                            </Button>
                            <Button
                              variant="outline"
                              onClick={() => setIsAddingMethod(false)}
                            >
                              Cancel
                            </Button>
                          </div>
                        </div>
                      </Show>

                      <Show
                        when={isLoadingMethods()}
                      >
                        <div
                          class="py-4 text-center"
                        >
                          <p
                            class="text-sm text-gray-500"
                          >
                            Loading 2FA methods...
                          </p>
                        </div>
                      </Show>

                      <Show
                        when={!isLoadingMethods() && twoFactorMethods().length > 0}
                      >
                        <div
                          class="mt-6"
                        >
                          <h3
                            class="font-medium mb-2"
                          >
                            Your 2FA Methods
                          </h3>
                          <div
                            class="border rounded-md divide-y"
                          >
                            <For
                              each={twoFactorMethods()}
                            >
                              {method => (
                                <div
                                  class="p-4 flex justify-between items-center"
                                >
                                  <div>
                                    <div
                                      class="font-medium capitalize"
                                    >
                                      {method.type}
                                    </div>
                                    <div
                                      class="text-sm text-gray-500"
                                    >
                                      Status:
                                      {' '}
                                      {method.enabled ? (
                                        <span
                                          class="text-green-600 font-medium"
                                        >
                                          Enabled
                                        </span>
                                      ) : (
                                        <span
                                          class="text-red-600 font-medium"
                                        >
                                          Disabled
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                  <div
                                    class="flex space-x-2"
                                  >
                                    <button
                                      class={`px-3 py-1 rounded-md text-sm font-medium ${method.enabled
                                        ? 'bg-red-100 text-red-700 hover:bg-red-200'
                                        : 'bg-green-100 text-green-700 hover:bg-green-200'}`}
                                      onClick={async () => {
                                        setError(null);
                                        setSuccess(null);
                                        setIsLoading(true);
                                        try {
                                          await request(`/profile/2fa/${method.enabled
                                            ? 'disable'
                                            : 'enable'}`, {
                                            method: 'POST',
                                            headers: {
                                              'Content-Type': 'application/json',
                                            },
                                            body: JSON.stringify({
                                              twofa_type: method.type,
                                            }),
                                          });
                                          setSuccess(`${method.type} 2FA method ${method.enabled
                                            ? 'disabled'
                                            : 'enabled'} successfully`);
                                          fetch2FAMethods();
                                        }
                                        catch (err) {
                                          const errorDetails = extractErrorDetails(err);
                                          setError(errorDetails.message || `Failed to ${method.enabled
                                            ? 'disable'
                                            : 'enable'} ${method.type} 2FA method`);
                                        }
                                        finally {
                                          setIsLoading(false);
                                        }
                                      }}
                                    >
                                      {method.enabled ? 'Disable' : 'Enable'}
                                    </button>
                                    <button
                                      class="px-3 py-1 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                                      onClick={async () => {
                                        if (confirm(`Are you sure you want to delete this ${method.type} 2FA method?`)) {
                                          setError(null);
                                          setSuccess(null);
                                          setIsLoading(true);
                                          try {
                                            await request('/profile/2fa/delete', {
                                              method: 'POST',
                                              headers: {
                                                'Content-Type': 'application/json',
                                              },
                                              body: JSON.stringify({
                                                twofa_type: method.type,
                                                twofa_id: method.two_factor_id,
                                              }),
                                            });
                                            setSuccess(`${method.type} 2FA method deleted successfully`);
                                            fetch2FAMethods();
                                          }
                                          catch (err) {
                                            const errorDetails = extractErrorDetails(err);
                                            setError(errorDetails.message || `Failed to delete ${method.type} 2FA method`);
                                          }
                                          finally {
                                            setIsLoading(false);
                                          }
                                        }
                                      }}
                                    >
                                      <div
                                        class="flex items-center"
                                      >
                                        <svg
                                          class="h-4 w-4 mr-1"
                                          fill="none"
                                          stroke="currentColor"
                                          viewBox="0 0 24 24"
                                          xmlns="http://www.w3.org/2000/svg"
                                        >
                                          <path
                                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                            stroke-width="2"
                                          />
                                        </svg>
                                        Delete
                                      </div>
                                    </button>
                                  </div>
                                </div>
                              )}
                            </For>
                          </div>

                          <Show
                            when={!isAddingMethod()}
                          >
                            <div
                              class="mt-4 flex justify-end"
                            >
                              <button
                                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                                onClick={() => setIsAddingMethod(true)}
                              >
                                Add 2FA Method
                              </button>
                            </div>
                          </Show>
                        </div>
                      </Show>

                      <Show
                        when={!isLoadingMethods() && twoFactorMethods().length === 0 && !isAddingMethod()}
                      >
                        <div
                          class="py-4 border rounded-md text-center"
                        >
                          <p
                            class="text-sm text-gray-500 mb-4"
                          >
                            You don't have any 2FA methods set up yet.
                          </p>

                          <div
                            class="flex justify-center"
                          >
                            <button
                              class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                              onClick={() => setIsAddingMethod(true)}
                            >
                              Add 2FA Method
                            </button>
                          </div>
                        </div>
                      </Show>
                    </div>

                    {/* QR code section removed as TOTP is not supported */}

                    <Show
                      when={backupCodes()}
                    >
                      <div
                        class="mt-4 space-y-4"
                      >
                        <h4
                          class="font-medium"
                        >
                          Backup Codes
                        </h4>
                        <p
                          class="text-sm text-gray-600"
                        >
                          Save these backup codes in a secure place. You can use them to access your account if you
                          lose access to your authenticator app.
                        </p>
                        <div
                          class="bg-gray-100 p-4 rounded-md"
                        >
                          <pre
                            class="text-sm"
                          >
                            {backupCodes()?.join('\n')}
                          </pre>
                        </div>
                      </div>
                    </Show>

                    {/* Removed the "Enter Code to Disable 2FA" block as requested */}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent
                value="accounts"
              >
                <AssociatedAccounts />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
