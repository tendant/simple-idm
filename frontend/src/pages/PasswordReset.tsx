import { Component, createSignal } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const PasswordReset: Component = () => {
  const params = useParams();
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const navigate = useNavigate();

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);

    if (password() !== confirmPassword()) {
      setError('Passwords do not match');
      return;
    }

    try {
      const response = await fetch('/auth/password/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: params.code,
          new_password: password(),
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || 'Failed to reset password');
      }

      setSuccess('Password has been reset successfully. Redirecting to login page...');
      
      // Redirect to login page after 2 seconds
      setTimeout(() => {
        navigate('/login');
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset password');
    }
  };

  return (
    <div class="container mx-auto flex h-screen w-screen flex-col items-center justify-center">
      {success() && (
        <Alert class="mb-4 w-[400px]">
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{success()}</AlertDescription>
        </Alert>
      )}
      {error() && (
        <Alert class="mb-4 w-[400px]" variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error()}</AlertDescription>
        </Alert>
      )}
      <Card class="w-[400px]">
        <CardHeader>
          <CardTitle>Reset Password</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} class="space-y-4">

            <div class="space-y-2">
              <Label for="password">New Password</Label>
              <Input
                id="password"
                type="password"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                placeholder="Enter new password"
                required
              />
            </div>
            <div class="space-y-2">
              <Label for="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                value={confirmPassword()}
                onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                placeholder="Confirm new password"
                required
              />
            </div>
            {error() && (
              <Alert class="mt-4" variant="destructive">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error()}</AlertDescription>
              </Alert>
            )}
            <div class="space-y-2">
              <Button type="submit" class="w-full">
                Reset Password
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => navigate('/login')}
                class="w-full"
              >
                Back to Login
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

export default PasswordReset;
