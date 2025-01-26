import { Component, createSignal } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const PasswordResetInit: Component = () => {
  const [email, setEmail] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal(false);
  const [loading, setLoading] = createSignal(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    
    try {
      const response = await fetch('/auth/password/reset/init', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email() }),
      });

      if (!response.ok) {
        const data = await response.text();
        throw new Error(data || 'Failed to initiate password reset');
      }
      
      setSuccess(true);
    } catch (err) {
      console.error('Password reset error:', err);
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="container mx-auto flex h-screen w-screen flex-col items-center justify-center">
      <Card class="w-[400px]">
        <CardHeader>
          <CardTitle>Reset Password</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} class="space-y-4">
            {success() ? (
              <div class="space-y-4">
                <Alert>
                  <AlertTitle>Check Your Email</AlertTitle>
                  <AlertDescription>
                    If an account exists with that email, we have sent password reset instructions.
                  </AlertDescription>
                </Alert>
                <Button 
                  type="button"
                  onClick={() => navigate('/login')}
                  class="w-full"
                >
                  Back to Login
                </Button>
              </div>
            ) : (
              <>
                <div class="space-y-2">
                  <Label for="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email()}
                    onChange={(e) => setEmail(e.currentTarget.value)}
                    placeholder="Enter your email"
                    required
                  />
                </div>
                {error() && (
                  <Alert variant="destructive">
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error()}</AlertDescription>
                  </Alert>
                )}
                <div class="flex justify-between">
                  <Button
                    type="button"
                    onClick={() => navigate('/login')}
                    variant="outline"
                  >
                    Back to Login
                  </Button>
                  <Button type="submit" disabled={loading()}>
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
