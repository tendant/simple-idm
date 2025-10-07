import { Component, createSignal, onMount, Show } from 'solid-js';
import { emailVerificationApi } from '../api/emailVerification';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Alert, AlertDescription, AlertTitle } from './ui/alert';

export const EmailVerificationStatus: Component = () => {
  const [emailVerified, setEmailVerified] = createSignal<boolean | null>(null);
  const [verifiedAt, setVerifiedAt] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [resending, setResending] = createSignal(false);
  const [message, setMessage] = createSignal<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchStatus = async () => {
    try {
      const status = await emailVerificationApi.getVerificationStatus();
      setEmailVerified(status.email_verified);
      setVerifiedAt(status.verified_at || null);
    } catch (error: any) {
      console.error('Failed to fetch verification status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResending(true);
    setMessage(null);

    try {
      const response = await emailVerificationApi.resendVerification();
      setMessage({ type: 'success', text: response.message || 'Verification email sent!' });
    } catch (error: any) {
      const errorMessage = error?.response?.data?.error || error?.message || 'Failed to send verification email';

      if (errorMessage.includes('already verified')) {
        setMessage({ type: 'error', text: 'Your email is already verified.' });
      } else if (errorMessage.includes('rate limit')) {
        setMessage({ type: 'error', text: 'Too many verification emails sent. Please try again later.' });
      } else {
        setMessage({ type: 'error', text: errorMessage });
      }
    } finally {
      setResending(false);
    }
  };

  onMount(() => {
    fetchStatus();
  });

  if (loading()) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Email Verification</CardTitle>
        </CardHeader>
        <CardContent>
          <div class="flex items-center justify-center py-4">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Email Verification</CardTitle>
      </CardHeader>
      <CardContent class="space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <Show
              when={emailVerified()}
              fallback={
                <>
                  <svg
                    class="h-5 w-5 text-yellow-500"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                  <span class="text-sm text-gray-700">Email not verified</span>
                </>
              }
            >
              <svg
                class="h-5 w-5 text-green-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span class="text-sm text-gray-700">
                Email verified
                {verifiedAt() && (
                  <span class="text-xs text-gray-500 ml-2">
                    on {new Date(verifiedAt()!).toLocaleDateString()}
                  </span>
                )}
              </span>
            </Show>
          </div>

          <Show when={!emailVerified()}>
            <Button
              onClick={handleResend}
              disabled={resending()}
              variant="outline"
              size="sm"
            >
              {resending() ? 'Sending...' : 'Resend Verification Email'}
            </Button>
          </Show>
        </div>

        <Show when={!emailVerified()}>
          <Alert>
            <AlertTitle>Verification Required</AlertTitle>
            <AlertDescription>
              Please check your email and click the verification link to verify your email address.
            </AlertDescription>
          </Alert>
        </Show>

        <Show when={message()}>
          <Alert variant={message()!.type === 'error' ? 'destructive' : 'default'}>
            <AlertDescription>{message()!.text}</AlertDescription>
          </Alert>
        </Show>
      </CardContent>
    </Card>
  );
};
