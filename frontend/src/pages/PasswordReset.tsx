import { Component, createSignal } from 'solid-js';
import { useNavigate, useParams, useSearchParams } from '@solidjs/router';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const PasswordReset: Component = () => {
  const params = useParams();
  const [searchParams] = useSearchParams();
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const navigate = useNavigate();
  
  // Get token from either route params or query params
  const getToken = () => {
    return params.code || searchParams.token;
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);

    if (password() !== confirmPassword()) {
      setError('Passwords do not match');
      return;
    }

    try {
      const response = await fetch('/api/idm/auth/password/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: getToken(),
          new_password: password(),
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message || 'Failed to reset password');
      }

      const data = await response.json();
      setSuccess(data.message || 'Password has been reset successfully');
      
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
