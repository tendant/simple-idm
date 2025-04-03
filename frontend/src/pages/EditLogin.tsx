import { Input } from '@/components/Input';
import { useLocation, useNavigate, useParams } from '@solidjs/router';
import { Component, createSignal, onMount, Show } from 'solid-js';
import { loginApi, type Login } from '../api/login';
import { userApi, type User } from '../api/user';

const EditLogin: Component = () => {
  const params = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [login, setLogin] = createSignal<Login | null>(null);
  const [user, setUser] = createSignal<User | null>(null);
  const [username, setUsername] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [twoFactorEnabled, setTwoFactorEnabled] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [saving, setSaving] = createSignal(false);
  const [showPasswordSection, setShowPasswordSection] = createSignal(false);
  const [showTwoFactorSection, setShowTwoFactorSection] = createSignal(false);
  const [twoFactorSecret, setTwoFactorSecret] = createSignal('');
  const [twoFactorQrCode, setTwoFactorQrCode] = createSignal('');
  const [verificationCode, setVerificationCode] = createSignal('');
  const [backupCodes, setBackupCodes] = createSignal<string[]>([]);

  const fetchUserAndLogin = async () => {
    try {
      const userData = await userApi.getUser(params.id);
      setUser(userData);
      
      if (userData.login_id && userData.login_id !== "00000000-0000-0000-0000-000000000000") {
        const loginData = await loginApi.getLogin(userData.login_id);
        setLogin(loginData);
        setUsername(loginData.username);
        setTwoFactorEnabled(loginData.two_factor_enabled || false);
      } else {
        setError('User does not have a login');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch user or login');
    } finally {
      setLoading(false);
    }
  };

  const fetchLogin = async () => {
    try {
      const data = await loginApi.getLogin(params.id);
      setLogin(data);
      setUsername(data.username);
      setTwoFactorEnabled(data.two_factor_enabled || false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch login');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    
    setSaving(true);
    setError(null);

    try {
      const updateData: any = {
        username: username(),
      };

      await loginApi.updateLogin(login()?.id || params.id, updateData);
      
      // Check if we're coming from the users page
      const isFromUsersPage = location.pathname.includes('/users/');
      if (isFromUsersPage) {
        navigate('/users');
      } else {
        navigate('/logins');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update login');
      setSaving(false);
    }
  };

  const handlePasswordReset = async (e: Event) => {
    e.preventDefault();
    
    if (password() !== confirmPassword()) {
      setError('Passwords do not match');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await loginApi.resetPassword(login()?.id || params.id, password());
      setPassword('');
      setConfirmPassword('');
      setShowPasswordSection(false);
      alert('Password has been reset successfully');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset password');
    } finally {
      setSaving(false);
    }
  };

  const handleEnable2FA = async () => {
    setSaving(true);
    setError(null);

    try {
      const result = await loginApi.enable2FA(login()?.id || params.id);
      setTwoFactorSecret(result.secret);
      setTwoFactorQrCode(result.qrCode);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to enable 2FA');
    } finally {
      setSaving(false);
    }
  };

  const handleVerify2FA = async () => {
    setSaving(true);
    setError(null);

    try {
      const result = await loginApi.verify2FA(login()?.id || params.id, verificationCode());
      if (result) {
        setTwoFactorEnabled(true);
        setShowTwoFactorSection(false);
        alert('Two-factor authentication has been enabled successfully');
        fetchLogin();
      } else {
        setError('Invalid verification code');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to verify 2FA code');
    } finally {
      setSaving(false);
    }
  };

  const handleDisable2FA = async () => {
    if (!confirm('Are you sure you want to disable two-factor authentication?')) return;
    
    setSaving(true);
    setError(null);

    try {
      await loginApi.disable2FA(login()?.id || params.id, verificationCode());
      setTwoFactorEnabled(false);
      setShowTwoFactorSection(false);
      alert('Two-factor authentication has been disabled successfully');
      fetchLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disable 2FA');
    } finally {
      setSaving(false);
    }
  };

  const handleGenerateBackupCodes = async () => {
    setSaving(true);
    setError(null);

    try {
      const codes = await loginApi.generateBackupCodes(login()?.id || params.id);
      setBackupCodes(codes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate backup codes');
    } finally {
      setSaving(false);
    }
  };

  onMount(() => {
    // Check if we're coming from the users page
    const isFromUsersPage = location.pathname.includes('/users/');
    
    if (isFromUsersPage) {
      fetchUserAndLogin();
    } else {
      fetchLogin();
    }
  });

  return (
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="md:flex md:items-center md:justify-between">
        <div class="min-w-0 flex-1">
          <h2 class="text-2xl font-bold leading-7 text-gray-12 sm:truncate sm:text-3xl sm:tracking-tight">
            {user() ? `Edit Login for ${user()?.name || user()?.username || 'User'}` : 'Edit Login'}
          </h2>
        </div>
        <div class="mt-4 flex md:ml-4 md:mt-0">
          <button
            type="button"
            onClick={() => location.pathname.includes('/users/') ? navigate('/users') : navigate('/logins')}
            class="inline-flex items-center rounded-lg bg-white px-3 py-2 text-sm font-semibold text-gray-11 shadow-sm ring-1 ring-inset ring-gray-6 hover:bg-gray-3"
          >
            Cancel
          </button>
        </div>
      </div>

      <Show when={!loading()} fallback={<div class="mt-6 text-center">Loading...</div>}>
        <div class="mt-8 flow-root">
          <div class="overflow-hidden bg-white shadow rounded-lg">
            <form onSubmit={handleSubmit} class="px-4 py-5 sm:p-6">
              {error() && (
                <div class="mb-4 rounded-lg bg-red-50 p-4">
                  <div class="flex">
                    <div class="flex-shrink-0">
                      <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                      </svg>
                    </div>
                    <div class="ml-3">
                      <h3 class="text-sm font-medium text-red-800">{error()}</h3>
                    </div>
                  </div>
                </div>
              )}

              <div class="space-y-6">
                <div>
                  <label for="username" class="block text-sm font-medium text-gray-11">
                    Username <span class="text-red-500">*</span>
                  </label>
                  <div class="mt-1">
                    <Input
                      type="text"
                      name="username"
                      id="username"
                      required
                      value={username()}
                      onInput={(e) => setUsername(e.currentTarget.value)}
                    />
                  </div>
                </div>

                <div class="flex justify-end">
                  <button
                    type="submit"
                    disabled={saving()}
                    class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {saving() ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Password Reset Section */}
          <div class="mt-8 overflow-hidden bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12">Reset Password</h3>
              <div class="mt-2 max-w-xl text-sm text-gray-9">
                <p>Change the password for this login.</p>
              </div>
              <div class="mt-5">
                <button
                  type="button"
                  onClick={() => setShowPasswordSection(!showPasswordSection())}
                  class="inline-flex items-center rounded-lg bg-white px-3 py-2 text-sm font-semibold text-gray-11 shadow-sm ring-1 ring-inset ring-gray-6 hover:bg-gray-3"
                >
                  {showPasswordSection() ? 'Hide Password Form' : 'Reset Password'}
                </button>
              </div>
              
              <Show when={showPasswordSection()}>
                <form onSubmit={handlePasswordReset} class="mt-5 space-y-4">
                  <div>
                    <label for="new-password" class="block text-sm font-medium text-gray-11">
                      New Password <span class="text-red-500">*</span>
                    </label>
                    <div class="mt-1">
                      <Input
                        type="password"
                        name="new-password"
                        id="new-password"
                        required
                        value={password()}
                        onInput={(e) => setPassword(e.currentTarget.value)}
                      />
                    </div>
                  </div>

                  <div>
                    <label for="confirm-password" class="block text-sm font-medium text-gray-11">
                      Confirm Password <span class="text-red-500">*</span>
                    </label>
                    <div class="mt-1">
                      <Input
                        type="password"
                        name="confirm-password"
                        id="confirm-password"
                        required
                        value={confirmPassword()}
                        onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                      />
                    </div>
                  </div>

                  <div class="flex justify-end">
                    <button
                      type="submit"
                      disabled={saving()}
                      class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {saving() ? 'Resetting...' : 'Reset Password'}
                    </button>
                  </div>
                </form>
              </Show>
            </div>
          </div>

          {/* Two-Factor Authentication Section */}
          <div class="mt-8 overflow-hidden bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
              <h3 class="text-lg font-medium leading-6 text-gray-12">Two-Factor Authentication</h3>
              <div class="mt-2 max-w-xl text-sm text-gray-9">
                <p>
                  {twoFactorEnabled() 
                    ? 'Two-factor authentication is currently enabled. You can disable it or generate new backup codes.' 
                    : 'Add an extra layer of security to the account by enabling two-factor authentication.'}
                </p>
              </div>
              <div class="mt-5">
                <button
                  type="button"
                  onClick={() => {
                    setShowTwoFactorSection(!showTwoFactorSection());
                    if (!showTwoFactorSection() && !twoFactorEnabled()) {
                      handleEnable2FA();
                    }
                  }}
                  class="inline-flex items-center rounded-lg bg-white px-3 py-2 text-sm font-semibold text-gray-11 shadow-sm ring-1 ring-inset ring-gray-6 hover:bg-gray-3"
                >
                  {showTwoFactorSection() 
                    ? 'Hide 2FA Settings' 
                    : twoFactorEnabled() 
                      ? 'Manage 2FA' 
                      : 'Enable 2FA'}
                </button>
              </div>
              
              <Show when={showTwoFactorSection()}>
                <div class="mt-5 space-y-4">
                  <Show when={!twoFactorEnabled() && twoFactorQrCode()}>
                    <div>
                      <h4 class="text-md font-medium text-gray-11">Scan this QR code with your authenticator app</h4>
                      <div class="mt-2">
                        <img src={twoFactorQrCode()} alt="QR Code for 2FA" class="h-48 w-48" />
                      </div>
                      <div class="mt-2">
                        <p class="text-sm text-gray-9">
                          Or enter this code manually: <code class="bg-gray-3 px-2 py-1 rounded">{twoFactorSecret()}</code>
                        </p>
                      </div>
                    </div>
                  </Show>

                  <div>
                    <label for="verification-code" class="block text-sm font-medium text-gray-11">
                      Verification Code <span class="text-red-500">*</span>
                    </label>
                    <div class="mt-1">
                      <Input
                        type="text"
                        name="verification-code"
                        id="verification-code"
                        required
                        value={verificationCode()}
                        onInput={(e) => setVerificationCode(e.currentTarget.value)}
                        placeholder="Enter the 6-digit code from your authenticator app"
                      />
                    </div>
                  </div>

                  <div class="flex justify-end space-x-3">
                    <Show when={twoFactorEnabled()}>
                      <button
                        type="button"
                        onClick={handleGenerateBackupCodes}
                        disabled={saving()}
                        class="inline-flex justify-center rounded-lg border border-transparent bg-gray-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {saving() ? 'Generating...' : 'Generate Backup Codes'}
                      </button>
                      <button
                        type="button"
                        onClick={handleDisable2FA}
                        disabled={saving()}
                        class="inline-flex justify-center rounded-lg border border-transparent bg-red-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {saving() ? 'Disabling...' : 'Disable 2FA'}
                      </button>
                    </Show>
                    <Show when={!twoFactorEnabled()}>
                      <button
                        type="button"
                        onClick={handleVerify2FA}
                        disabled={saving() || !verificationCode()}
                        class="inline-flex justify-center rounded-lg border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {saving() ? 'Verifying...' : 'Verify and Enable 2FA'}
                      </button>
                    </Show>
                  </div>

                  <Show when={backupCodes().length > 0}>
                    <div class="mt-4">
                      <h4 class="text-md font-medium text-gray-11">Backup Codes</h4>
                      <p class="text-sm text-gray-9 mt-1">
                        Save these backup codes in a secure location. Each code can only be used once.
                      </p>
                      <div class="mt-2 bg-gray-3 p-4 rounded-lg">
                        <ul class="grid grid-cols-2 gap-2">
                          {backupCodes().map((code) => (
                            <li class="text-mono text-sm">{code}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </Show>
                </div>
              </Show>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default EditLogin;
