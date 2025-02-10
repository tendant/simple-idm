import { Component, createSignal, Show } from 'solid-js';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import Navigation from '@/components/Navigation';

const Settings: Component = () => {
  const [currentPassword, setCurrentPassword] = createSignal('');
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [twoFactorEnabled, setTwoFactorEnabled] = createSignal(false);
  const [qrCode, setQrCode] = createSignal<string | null>(null);
  const [backupCodes, setBackupCodes] = createSignal<string[] | null>(null);
  const [twoFactorCode, setTwoFactorCode] = createSignal('');

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword() !== confirmPassword()) {
      setError('New passwords do not match');
      return;
    }

    try {
      const response = await fetch('/profile/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          currentPassword: currentPassword(),
          newPassword: newPassword(),
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message || 'Failed to change password');
      }

      setSuccess('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
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
                    When enabled, you'll need to enter both your password and a code from your
                    authenticator app when signing in.
                  </p>
                  <Button
                    onClick={async () => {
                      try {
                        const response = await fetch('/profile/2fa/setup', {
                          method: 'POST'
                        });
                        if (!response.ok) throw new Error('Failed to setup 2FA');
                        const data = await response.json();
                        setQrCode(data.qrCode);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to setup 2FA');
                      }
                    }}
                  >
                    Setup 2FA
                  </Button>
                </div>
              </Show>

              <Show when={qrCode() && !twoFactorEnabled()}>
                <div class="mt-4 space-y-4">
                  <img src={qrCode()} alt="2FA QR Code" class="w-48 h-48" />
                  <p class="text-sm text-gray-600">
                    Scan this QR code with your authenticator app, then enter the code below to enable 2FA.
                  </p>
                  <div class="space-y-2">
                    <Label for="2fa-code">Authentication Code</Label>
                    <Input
                      id="2fa-code"
                      type="text"
                      value={twoFactorCode()}
                      onInput={(e) => setTwoFactorCode(e.currentTarget.value)}
                      required
                    />
                  </div>
                  <Button
                    onClick={async () => {
                      try {
                        const response = await fetch('/profile/2fa/enable', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                          },
                          body: JSON.stringify({
                            code: twoFactorCode()
                          }),
                        });
                        if (!response.ok) throw new Error('Failed to enable 2FA');
                        const data = await response.json();
                        setBackupCodes(data.backupCodes);
                        setTwoFactorEnabled(true);
                        setQrCode(null);
                        setSuccess('2FA enabled successfully');
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to enable 2FA');
                      }
                    }}
                  >
                    Enable 2FA
                  </Button>
                </div>
              </Show>

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
                        const response = await fetch('/profile/2fa/disable', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                          },
                          body: JSON.stringify({
                            code: twoFactorCode()
                          }),
                        });
                        if (!response.ok) throw new Error('Failed to disable 2FA');
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
