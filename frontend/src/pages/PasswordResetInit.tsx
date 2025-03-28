import { useNavigate } from '@solidjs/router';
import type { Component } from 'solid-js';
import { createSignal } from 'solid-js';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const PasswordResetInit: Component = () => {
  const [username, setUsername] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal(false);
  const [loading, setLoading] = createSignal(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch('/api/idm/auth/password/reset/init', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username: username() }),
      });

      if (!response.ok) {
        const data = await response.text();
        throw new Error(data || 'Failed to initiate password reset');
      }

      setSuccess(true);
    }
    catch (err) {
      console.error('Password reset error:', err);
      setError(err instanceof Error
        ? err.message
        : 'An unexpected error occurred');
    }
    finally {
      setLoading(false);
    }
  };

  return (
    <div
      class="container mx-auto flex h-screen w-screen flex-col items-center justify-center"
    >
      <Card
        class="w-[400px]"
      >
        <CardHeader>
          <CardTitle>Reset Password</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            class="space-y-4"
            onSubmit={handleSubmit}
          >
            {success()
              ? (
                  <div
                    class="space-y-4"
                  >
                    <Alert>
                      <AlertTitle>Check Your Email</AlertTitle>
                      <AlertDescription>
                        If an account exists with that username, we have sent password reset instructions.
                      </AlertDescription>
                    </Alert>
                    <Button
                      class="w-full"
                      type="button"
                      onClick={() => navigate('/login')}
                    >
                      Back to Login
                    </Button>
                  </div>
                )
              : (
                  <>
                    <div
                      class="space-y-2"
                    >
                      <Label
                        for="username"
                      >
                        Username
                      </Label>
                      <Input
                        required
                        id="username"
                        placeholder="Enter your username"
                        type="text"
                        value={username()}
                        onChange={e => setUsername(e.currentTarget.value)}
                      />
                    </div>
                    {error() && (
                      <Alert
                        variant="destructive"
                      >
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>
                          {error()}
                        </AlertDescription>
                      </Alert>
                    )}
                    <div
                      class="flex justify-between"
                    >
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => navigate('/login')}
                      >
                        Back to Login
                      </Button>
                      <Button
                        disabled={loading()}
                        type="submit"
                      >
                        {loading() ? 'Sending...' : 'Send Reset Instructions'}
                      </Button>
                    </div>
                  </>
                )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

export default PasswordResetInit;
