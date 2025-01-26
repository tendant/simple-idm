import { Component, createSignal } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { Button } from "~/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Input } from "~/components/ui/input";
import { Label } from "~/components/ui/label";
import { Alert, AlertDescription } from "~/components/ui/alert";

const PasswordResetInit: Component = () => {
  const [email, setEmail] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    
    try {
      const response = await fetch('/api/password/reset/init', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email() }),
      });

      if (!response.ok) {
        throw new Error('Failed to initiate password reset');
      }

      setSuccess(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to initiate password reset');
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
                <p class="text-sm text-muted-foreground">
                  If an account exists with that email, you will receive a password reset code.
                </p>
                <Button 
                  type="button"
                  onClick={() => navigate('/password-reset')}
                  class="w-full"
                >
                  Continue to Reset Password
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
                    onInput={(e) => setEmail(e.currentTarget.value)}
                    placeholder="Enter your email"
                    required
                  />
                </div>
                {error() && (
                  <Alert variant="destructive">
                    <AlertDescription>{error()}</AlertDescription>
                  </Alert>
                )}
                <div class="space-y-2">
                  <Button type="submit" class="w-full">
                    Send Reset Code
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
              </>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

export default PasswordResetInit;
