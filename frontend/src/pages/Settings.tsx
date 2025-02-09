import { Component, createSignal } from 'solid-js';
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

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword() !== confirmPassword()) {
      setError('New passwords do not match');
      return;
    }

    try {
      const response = await fetch('/auth/password/change', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: currentPassword(),
          new_password: newPassword(),
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
      <Navigation />
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
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
