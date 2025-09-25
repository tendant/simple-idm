import { Component, createSignal, onMount } from 'solid-js';
import { useNavigate, useParams, useSearchParams } from '@solidjs/router';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { loginApi, PasswordPolicyResponse } from '@/api/login';

const PasswordReset: Component = () => {
  const params = useParams();
  const [searchParams] = useSearchParams();
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [policy, setPolicy] = createSignal<PasswordPolicyResponse | null>(null);
  const [policyLoading, setPolicyLoading] = createSignal(true);
  const navigate = useNavigate();
  
  // Get token from either route params or query params
  const getToken = () => {
    return params.code || searchParams.token;
  };

  // Fetch password policy on component mount
  onMount(async () => {
    const token = getToken();
    if (token) {
      try {
        // Ensure token is a string (handle array case)
        const tokenStr = Array.isArray(token) ? token[0] : token;
        const policyData = await loginApi.getPasswordResetPolicy(tokenStr);
        setPolicy(policyData);
      } catch (err) {
        console.error('Failed to fetch password policy:', err);
        // Don't show error to user, just continue without policy display
      } finally {
        setPolicyLoading(false);
      }
    } else {
      setPolicyLoading(false);
    }
  });

  // Helper function to check if passwords match
  const passwordsMatch = () => {
    return password() === confirmPassword() && password().length > 0;
  };

  // Helper function to check password requirements
  const checkRequirement = (requirement: string) => {
    const pwd = password();
    const policyData = policy();
    
    switch (requirement) {
      case 'length':
        return policyData?.min_length ? pwd.length >= policyData.min_length : true;
      case 'uppercase':
        return policyData?.require_uppercase ? /[A-Z]/.test(pwd) : true;
      case 'lowercase':
        return policyData?.require_lowercase ? /[a-z]/.test(pwd) : true;
      case 'digit':
        return policyData?.require_digit ? /\d/.test(pwd) : true;
      case 'special':
        return policyData?.require_special_char ? /[!@#$%^&*(),.?":{}|<>]/.test(pwd) : true;
      case 'repeated':
        if (!policyData?.max_repeated_chars) return true;
        const maxRepeated = policyData.max_repeated_chars;
        const regex = new RegExp(`(.)\\1{${maxRepeated},}`);
        return !regex.test(pwd);
      default:
        return true;
    }
  };

  // Helper function to check if all password requirements are met
  const allRequirementsMet = () => {
    const policyData = policy();
    if (!policyData) return true; // If no policy loaded, allow submission
    
    // Check all policy requirements
    const requirements = [
      checkRequirement('length'),
      checkRequirement('uppercase'),
      checkRequirement('lowercase'),
      checkRequirement('digit'),
      checkRequirement('special'),
      checkRequirement('repeated'),
      passwordsMatch()
    ];
    
    return requirements.every(req => req);
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
            
            {/* Password Requirements Display */}
            {!policyLoading() && policy() && (
              <div class="space-y-2">
                <Label class="text-sm font-medium">Password requirements:</Label>
                <div class="text-sm space-y-1">
                  {policy()?.min_length && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('length') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('length') ? '✓' : '•'}</span>
                      <span>Must be at least {policy()?.min_length} characters.</span>
                    </div>
                  )}
                  {policy()?.require_uppercase && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('uppercase') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('uppercase') ? '✓' : '•'}</span>
                      <span>Must contain at least one uppercase.</span>
                    </div>
                  )}
                  {policy()?.require_lowercase && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('lowercase') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('lowercase') ? '✓' : '•'}</span>
                      <span>Must contain at least one lowercase.</span>
                    </div>
                  )}
                  {policy()?.require_digit && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('digit') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('digit') ? '✓' : '•'}</span>
                      <span>Must contain at least one number.</span>
                    </div>
                  )}
                  {policy()?.require_special_char && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('special') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('special') ? '✓' : '•'}</span>
                      <span>Must contain at least one special character.</span>
                    </div>
                  )}
                  {policy()?.max_repeated_chars && (
                    <div class={`flex items-center space-x-2 ${checkRequirement('repeated') ? 'text-green-600' : 'text-gray-600'}`}>
                      <span>{checkRequirement('repeated') ? '✓' : '•'}</span>
                      <span>At most {policy()?.max_repeated_chars} repeated characters.</span>
                    </div>
                  )}
                  <div class={`flex items-center space-x-2 ${passwordsMatch() ? 'text-green-600' : 'text-gray-600'}`}>
                    <span>{passwordsMatch() ? '✓' : '•'}</span>
                    <span>Both passwords match.</span>
                  </div>
                </div>
              </div>
            )}
            {error() && (
              <Alert class="mt-4" variant="destructive">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error()}</AlertDescription>
              </Alert>
            )}
            <div class="space-y-2">
              <Button 
                type="submit" 
                class="w-full" 
                disabled={!allRequirementsMet()}
              >
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
