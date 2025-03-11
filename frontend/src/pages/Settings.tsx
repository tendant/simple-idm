import { Component, createSignal, Show, createEffect } from 'solid-js';
import { useApi } from '../lib/hooks/useApi';
import { extractErrorDetails } from '../lib/api';
import { twoFactorApi } from '../api/twoFactor';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import Navigation from '../components/Navigation';

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

  const { request } = useApi();

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
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      
      // Handle specific error codes
      if (errorDetails.code === 'invalid_password') {
        setError('Current password is incorrect');
      } else if (errorDetails.code === 'invalid_password_complexity') {
        // Display the specific password complexity error message
        setError(errorDetails.message);
      } else {
        // For any other error, display the message
        setError(errorDetails.message);
      }
    }
  };

  return (
    <div>
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div class="container mx-auto p-4">
          <div class="mx-auto max-w-2xl">
            <h1 class="mb-8 text-2xl font-bold">User Settings</h1>
        
        {success() && (
          <Alert class="mb-4">
            <AlertTitle>Success</AlertTitle>
            <AlertDescription>{success()}</AlertDescription>
          </Alert>
        )}
        
        {error() && (
          <Alert class="mb-4" variant="destructive">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error()}</AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="password" class="w-full">
          <TabsList class="grid w-full grid-cols-2">
            <TabsTrigger value="password">Password</TabsTrigger>
            <TabsTrigger value="2fa">Two-Factor Auth</TabsTrigger>
          </TabsList>

          <TabsContent value="password">
            <Card>
              <CardHeader>
                <CardTitle>Change Password</CardTitle>
              </CardHeader>
              <CardContent>
            <form onSubmit={handleSubmit} class="space-y-4">
              <div class="space-y-2">
                <Label for="current-password">Current Password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword()}
                  onInput={(e) => setCurrentPassword(e.currentTarget.value)}
                  required
                />
              </div>
              
              <div class="space-y-2">
                <Label for="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword()}
                  onInput={(e) => setNewPassword(e.currentTarget.value)}
                  required
                />
              </div>
              
              <div class="space-y-2">
                <Label for="confirm-password">Confirm New Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword()}
                  onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                  required
                />
              </div>

              <Button type="submit" class="w-full">
                Change Password
              </Button>
            </form>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="2fa">
        <Card>
          <CardHeader>
            <CardTitle>Two-Factor Authentication</CardTitle>
          </CardHeader>
          <CardContent>
              
              <Show when={!twoFactorEnabled()}>
                <div class="space-y-4">
                  <p class="text-sm text-gray-600">
                    Two-factor authentication adds an extra layer of security to your account.
                    When enabled, you'll need to enter both your password and a verification code
                    when signing in.
                  </p>
                  
                  <Show when={!isAddingMethod()}>
                    <Button
                      onClick={() => setIsAddingMethod(true)}
                    >
                      Add 2FA Method
                    </Button>
                  </Show>
                  
                  <Show when={isAddingMethod()}>
                    <div class="space-y-4 p-4 border rounded-md">
                      <h3 class="font-medium">Add 2FA Method</h3>
                      <div class="space-y-2">
                        <Label for="twofa-type">Authentication Type</Label>
                        <div class="relative">
                          <select 
                            id="twofa-type"
                            class="w-full h-10 rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                            value={twoFactorType()}
                            onChange={(e) => setTwoFactorType(e.target.value)}
                          >
                            <option value="email">Email</option>
                            <option value="sms">SMS</option>
                          </select>
                        </div>
                      </div>
                      
                      <div class="flex space-x-2">
                        <Button
                          onClick={async () => {
                            setError(null);
                            setSuccess(null);
                            setIsLoading(true);
                            try {
                              await twoFactorApi.setup2FAMethod(twoFactorType());
                              setSuccess(`${twoFactorType().toUpperCase()} 2FA method added successfully`);
                              setTwoFactorEnabled(true);
                              setIsAddingMethod(false);
                            } catch (err) {
                              const errorDetails = extractErrorDetails(err);
                              setError(errorDetails.message || `Failed to setup ${twoFactorType()} 2FA method`);
                            } finally {
                              setIsLoading(false);
                            }
                          }}
                          disabled={isLoading()}
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
                </div>
              </Show>

              {/* QR code section removed as TOTP is not supported */}

              <Show when={backupCodes()}>
                <div class="mt-4 space-y-4">
                  <h4 class="font-medium">Backup Codes</h4>
                  <p class="text-sm text-gray-600">
                    Save these backup codes in a secure place. You can use them to access your account if you
                    lose access to your authenticator app.
                  </p>
                  <div class="bg-gray-100 p-4 rounded-md">
                    <pre class="text-sm">
                      {backupCodes()?.join('\n')}
                    </pre>
                  </div>
                </div>
              </Show>

              <Show when={twoFactorEnabled()}>
                <div class="space-y-4">
                  <p class="text-sm text-gray-600">
                    Two-factor authentication is enabled. You'll need to enter a code from your
                    authenticator app when signing in.
                  </p>
                  <div class="space-y-2">
                    <Label for="disable-2fa-code">Enter Code to Disable 2FA</Label>
                    <Input
                      id="disable-2fa-code"
                      type="text"
                      value={twoFactorCode()}
                      onInput={(e) => setTwoFactorCode(e.currentTarget.value)}
                      required
                    />
                  </div>
                  <Button
                    variant="destructive"
                    onClick={async () => {
                      try {
                        await request('/profile/2fa/disable', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                          },
                          body: JSON.stringify({
                            code: twoFactorCode()
                          }),
                        });
                        setTwoFactorEnabled(false);
                        setTwoFactorCode('');
                        setSuccess('2FA disabled successfully');
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to disable 2FA');
                      }
                    }}
                  >
                    Disable 2FA
                  </Button>
                </div>
              </Show>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
