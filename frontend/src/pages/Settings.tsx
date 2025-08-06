import { Component, createSignal, Show, createEffect, For } from 'solid-js';
import { useApi } from '../lib/hooks/useApi';
import { extractErrorDetails } from '../lib/api';
import { twoFactorApi, ProfileTwoFactorMethod } from '../api/twoFactor';
import { profileApi } from '../api/profile';
import { Device } from '../api/device';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import { AssociatedAccounts } from '../components/AssociatedAccounts';
import Navigation from '../components/Navigation';

const Settings: Component = () => {
  const [currentPassword, setCurrentPassword] = createSignal('');
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [twoFactorEnabled, setTwoFactorEnabled] = createSignal(false);
  const [backupCodes, setBackupCodes] = createSignal<string[] | null>(null);
  const [twoFactorCode, setTwoFactorCode] = createSignal('');
  const [twoFactorType, setTwoFactorType] = createSignal<string>('email');
  const [isAddingMethod, setIsAddingMethod] = createSignal(false);
  const [isLoading, setIsLoading] = createSignal(false);
  const [twoFactorMethods, setTwoFactorMethods] = createSignal<ProfileTwoFactorMethod[]>([]);
  const [isLoadingMethods, setIsLoadingMethods] = createSignal(false);
  const [linkedDevices, setLinkedDevices] = createSignal<Device[]>([]);
  const [isLoadingDevices, setIsLoadingDevices] = createSignal(false);
  const [deviceError, setDeviceError] = createSignal<string | null>(null);
  const [editingDevice, setEditingDevice] = createSignal<string | null>(null);
  const [newDisplayName, setNewDisplayName] = createSignal('');
  
  // Phone verification state
  const [phone, setPhone] = createSignal('');
  const [verificationCode, setVerificationCode] = createSignal('');
  const [isVerificationSent, setIsVerificationSent] = createSignal(false);
  const [isVerifying, setIsVerifying] = createSignal(false);
  const [isPhoneVerified, setIsPhoneVerified] = createSignal(false);
  const [isUpdatingPhone, setIsUpdatingPhone] = createSignal(false);
  const [phoneError, setPhoneError] = createSignal<string | null>(null);
  const [phoneSuccess, setPhoneSuccess] = createSignal<string | null>(null);
  const [isLoadingProfile, setIsLoadingProfile] = createSignal(false);
  const [userProfile, setUserProfile] = createSignal<any>(null);

  const { request } = useApi();

  const fetch2FAMethods = async () => {
    setIsLoadingMethods(true);
    try {
      const data = await twoFactorApi.get2FAMethods();
      setTwoFactorMethods(data.methods || []);
      setTwoFactorEnabled(data.methods && data.methods.length > 0);
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      setError(errorDetails.message || 'Failed to fetch 2FA methods');
    } finally {
      setIsLoadingMethods(false);
    }
  };

  const fetchLinkedDevices = async () => {
    setIsLoadingDevices(true);
    setDeviceError(null);
    try {
      const devices = await profileApi.getMyDevices();
      setLinkedDevices(devices);
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      setDeviceError(errorDetails.message || 'Failed to fetch linked devices');
    } finally {
      setIsLoadingDevices(false);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const isExpiringSoon = (dateString: string) => {
    if (!dateString) return false;
    const expiryDate = new Date(dateString);
    const now = new Date();
    // Consider "expiring soon" if less than 7 days away
    const sevenDaysInMs = 7 * 24 * 60 * 60 * 1000;
    return expiryDate.getTime() - now.getTime() < sevenDaysInMs;
  };

  const handleUnlinkDevice = async (fingerprint: string) => {
    if (!confirm('Are you sure you want to unlink this device? You will need to verify this device again next time you use it.')) {
      return;
    }

    setIsLoading(true);
    setDeviceError(null);
    try {
      // Use the new profile API endpoint that doesn't require login ID
      await profileApi.unlinkDevice(fingerprint);
      await fetchLinkedDevices(); // Refresh the list
      setSuccess('Device unlinked successfully');
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      setDeviceError(errorDetails.message || 'Failed to unlink device');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword() !== confirmPassword()) {
      setError('New passwords do not match');
      return;
    }

    try {
      await request('/api/idm/profile/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: currentPassword(),
          new_password: newPassword(),
        }),
      });

      setSuccess('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      
      // Handle specific error codes
      if (errorDetails.code === 'invalid_password') {
        setError('Current password is incorrect');
      } else if (errorDetails.code === 'invalid_password_complexity') {
        // Display the specific password complexity error message
        setError(errorDetails.message);
      } else {
        // For any other error, display the message
        setError(errorDetails.message);
      }
    }
  };

  const handleEditDevice = (device: Device) => {
    setEditingDevice(device.fingerprint);
    setNewDisplayName(device.display_name || device.device_name || '');
  };

  const handleSaveDeviceName = async () => {
    const fingerprint = editingDevice();
    if (!fingerprint) return;

    setIsLoading(true);
    try {
      const response = await profileApi.updateDeviceDisplayName(fingerprint, newDisplayName());
      
      // Update the device in the local state
      const updatedDevices = linkedDevices().map(device => {
        if (device.fingerprint === fingerprint) {
          return { ...device, display_name: newDisplayName() };
        }
        return device;
      });
      
      setLinkedDevices(updatedDevices);
      setEditingDevice(null);
      setSuccess('Device name updated successfully');
    } catch (err) {
      const errorDetails = extractErrorDetails(err);
      setDeviceError(errorDetails.message || 'Failed to update device name');
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch user profile
  const fetchUserProfile = async () => {
    setIsLoadingProfile(true);
    try {
      const profiles = await profileApi.getProfile();
      if (profiles && profiles.length > 0) {
        setUserProfile(profiles[0]);
      }
    } catch (err) {
      console.error('Failed to fetch user profile:', err);
    } finally {
      setIsLoadingProfile(false);
    }
  };
  
  // Fetch user's phone number
  const fetchUserPhone = async () => {
    try {
      const data = await profileApi.getPhone();
      if (data.phone) {
        setPhone(data.phone);
      }
    } catch (err) {
      console.error('Failed to fetch phone number:', err);
    }
  };

  // Fetch 2FA methods when component mounts
  createEffect(() => {
    fetch2FAMethods();
    fetchLinkedDevices();
    fetchUserProfile();
    fetchUserPhone(); // Add this line to fetch the phone number
  });

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
          <TabsList class="grid w-full grid-cols-5">
            <TabsTrigger value="password">Password</TabsTrigger>
            <TabsTrigger value="phone">Phone</TabsTrigger>
            <TabsTrigger value="2fa">Two-Factor Auth</TabsTrigger>
            <TabsTrigger value="devices">Devices</TabsTrigger>
            <TabsTrigger value="accounts">Associated Accounts</TabsTrigger>
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

      <TabsContent value="phone">
        <Card>
          <CardHeader>
            <CardTitle>Phone Number</CardTitle>
          </CardHeader>
          <CardContent>
            {phoneError() && (
              <Alert class="mb-4" variant="destructive">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{phoneError()}</AlertDescription>
              </Alert>
            )}
            
            {phoneSuccess() && (
              <Alert class="mb-4">
                <AlertTitle>Success</AlertTitle>
                <AlertDescription>{phoneSuccess()}</AlertDescription>
              </Alert>
            )}
            
            <div class="space-y-4">
              <p class="text-sm text-gray-600">
                Add or update your phone number. A verification code will be sent to your phone to confirm it's yours.
              </p>
              
              <Show when={isLoadingProfile()}>
                <div class="py-4 text-center">
                  <p class="text-sm text-gray-500">Loading profile information...</p>
                </div>
              </Show>
              
              <div class="space-y-2">
                <Label for="phone-number">Phone Number</Label>
                <Input
                  id="phone-number"
                  type="tel"
                  value={phone()}
                  onInput={(e) => setPhone(e.currentTarget.value)}
                  disabled={isVerifying()}
                  placeholder={isLoadingProfile() ? "Loading..." : "Enter your phone number"}
                />
              </div>
              
              <Show when={!isVerificationSent() && !isPhoneVerified()}>
                <Button
                  onClick={async () => {
                    if (!phone()) {
                      setPhoneError('Phone number is required');
                      return;
                    }
                    
                    setPhoneError(null);
                    setPhoneSuccess(null);
                    setIsVerifying(true);
                    
                    try {
                      await profileApi.sendPhoneVerification(phone());
                      setIsVerificationSent(true);
                      setPhoneSuccess('Verification code sent successfully');
                    } catch (err) {
                      if (err instanceof Error) {
                        setPhoneError(err.message);
                      } else {
                        setPhoneError('Failed to send verification code');
                      }
                    } finally {
                      setIsVerifying(false);
                    }
                  }}
                  disabled={isVerifying() || !phone()}
                  class="w-full"
                >
                  {isVerifying() ? 'Sending...' : 'Send Verification Code'}
                </Button>
              </Show>
              
              <Show when={isPhoneVerified()}>
                <Button
                  onClick={async () => {
                    setPhoneError(null);
                    setPhoneSuccess(null);
                    setIsUpdatingPhone(true);
                    
                    try {
                      await profileApi.updatePhone(phone());
                      setPhoneSuccess('Phone number updated successfully');
                      setIsPhoneVerified(false);
                    } catch (err) {
                      if (err instanceof Error) {
                        setPhoneError(err.message);
                      } else {
                        setPhoneError('Failed to update phone number');
                      }
                    } finally {
                      setIsUpdatingPhone(false);
                    }
                  }}
                  disabled={isUpdatingPhone()}
                  class="w-full"
                >
                  {isUpdatingPhone() ? 'Updating...' : 'Update Phone Number'}
                </Button>
                
                <Button
                  variant="outline"
                  onClick={() => {
                    setIsPhoneVerified(false);
                    setPhoneSuccess(null);
                    setPhoneError(null);
                  }}
                  disabled={isUpdatingPhone()}
                  class="w-full mt-2"
                >
                  Cancel
                </Button>
              </Show>
              
              <Show when={isVerificationSent()}>
                <div class="space-y-2">
                  <Label for="verification-code">Verification Code</Label>
                  <Input
                    id="verification-code"
                    type="text"
                    placeholder="Enter the 6-digit code"
                    value={verificationCode()}
                    onInput={(e) => setVerificationCode(e.currentTarget.value)}
                    disabled={isVerifying()}
                  />
                </div>
                
                <div class="flex space-x-2">
                  <Button
                    onClick={async () => {
                      if (!verificationCode()) {
                        setPhoneError('Verification code is required');
                        return;
                      }
                      
                      setPhoneError(null);
                      setPhoneSuccess(null);
                      setIsVerifying(true);
                      
                      try {
                        await profileApi.verifyPhone(phone(), verificationCode());
                        setPhoneSuccess('Phone number verified successfully. Click "Update Phone Number" to save it.');
                        setIsVerificationSent(false);
                        setVerificationCode('');
                        setIsPhoneVerified(true);
                      } catch (err) {
                        if (err instanceof Error) {
                          setPhoneError(err.message);
                        } else {
                          setPhoneError('Failed to verify phone number');
                        }
                      } finally {
                        setIsVerifying(false);
                      }
                    }}
                    disabled={isVerifying() || !verificationCode()}
                    class="flex-1"
                  >
                    {isVerifying() ? 'Verifying...' : 'Verify Phone Number'}
                  </Button>
                  
                  <Button
                    variant="outline"
                    onClick={() => {
                      setIsVerificationSent(false);
                      setVerificationCode('');
                      setPhoneError(null);
                      setPhoneSuccess(null);
                    }}
                    disabled={isVerifying()}
                  >
                    Cancel
                  </Button>
                </div>
                
                <Button
                  variant="ghost"
                  onClick={async () => {
                    setPhoneError(null);
                    setPhoneSuccess(null);
                    setIsVerifying(true);
                    
                    try {
                      await profileApi.sendPhoneVerification(phone());
                      setPhoneSuccess('Verification code resent successfully');
                    } catch (err) {
                      if (err instanceof Error) {
                        setPhoneError(err.message);
                      } else {
                        setPhoneError('Failed to resend verification code');
                      }
                    } finally {
                      setIsVerifying(false);
                    }
                  }}
                  disabled={isVerifying()}
                  class="w-full text-sm"
                >
                  Resend Verification Code
                </Button>
              </Show>
            </div>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="2fa">
        <Card>
          <CardHeader>
            <CardTitle>Two-Factor Authentication</CardTitle>
          </CardHeader>
          <CardContent>
              
              <div class="space-y-4">
                <p class="text-sm text-gray-600">
                  Two-factor authentication adds an extra layer of security to your account.
                  When enabled, you'll need to enter both your password and a verification code
                  when signing in.
                </p>
                  
                  <Show when={isAddingMethod()}>
                    <div class="space-y-4 p-4 border rounded-md">
                      <h3 class="font-medium">Add 2FA Method</h3>
                      <div class="space-y-2">
                        <Label for="twofa-type">Authentication Type</Label>
                        <div class="relative">
                          <select 
                            id="twofa-type"
                            class="w-full h-10 rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                            value={twoFactorType()}
                            onChange={(e) => setTwoFactorType(e.target.value)}
                          >
                            <option value="email">Email</option>
                            <option value="sms">SMS</option>
                          </select>
                        </div>
                      </div>
                      
                      <div class="flex space-x-2">
                        <Button
                          onClick={async () => {
                            setError(null);
                            setSuccess(null);
                            setIsLoading(true);
                            try {
                              await twoFactorApi.setup2FAMethod(twoFactorType());
                              setSuccess(`${twoFactorType().toUpperCase()} 2FA method added successfully`);
                              setTwoFactorEnabled(true);
                              setIsAddingMethod(false);
                              fetch2FAMethods();
                            } catch (err) {
                              const errorDetails = extractErrorDetails(err);
                              setError(errorDetails.message || `Failed to setup ${twoFactorType()} 2FA method`);
                            } finally {
                              setIsLoading(false);
                            }
                          }}
                          disabled={isLoading()}
                        >
                          {isLoading() ? 'Adding...' : 'Add Method'}
                        </Button>
                        <Button 
                          variant="outline"
                          onClick={() => setIsAddingMethod(false)}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  </Show>
                  
                  <Show when={isLoadingMethods()}>
                    <div class="py-4 text-center">
                      <p class="text-sm text-gray-500">Loading 2FA methods...</p>
                    </div>
                  </Show>
                  
                  <Show when={!isLoadingMethods() && twoFactorMethods().length > 0}>
                    <div class="mt-6">
                      <h3 class="font-medium mb-2">Your 2FA Methods</h3>
                      <div class="border rounded-md divide-y">
                        <For each={twoFactorMethods()}>
                          {(method) => (
                            <div class="p-4 flex justify-between items-center">
                              <div>
                                <div class="font-medium capitalize">{method.type}</div>
                                <div class="text-sm text-gray-500">
                                  Status: {method.enabled ? (
                                    <span class="text-green-600 font-medium">Enabled</span>
                                  ) : (
                                    <span class="text-red-600 font-medium">Disabled</span>
                                  )}
                                </div>
                              </div>
                              <div class="flex space-x-2">
                                <button
                                  onClick={async () => {
                                    setError(null);
                                    setSuccess(null);
                                    setIsLoading(true);
                                    try {
                                      await request(`/api/idm/profile/2fa/${method.enabled ? 'disable' : 'enable'}`, {
                                        method: 'POST',
                                        headers: {
                                          'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({
                                          twofa_type: method.type
                                        })
                                      });
                                      setSuccess(`${method.type} 2FA method ${method.enabled ? 'disabled' : 'enabled'} successfully`);
                                      fetch2FAMethods();
                                    } catch (err) {
                                      const errorDetails = extractErrorDetails(err);
                                      setError(errorDetails.message || `Failed to ${method.enabled ? 'disable' : 'enable'} ${method.type} 2FA method`);
                                    } finally {
                                      setIsLoading(false);
                                    }
                                  }}
                                  class={`px-3 py-1 rounded-md text-sm font-medium ${method.enabled 
                                    ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                                    : 'bg-green-100 text-green-700 hover:bg-green-200'}`}
                                >
                                  {method.enabled ? 'Disable' : 'Enable'}
                                </button>
                                <button
                                  onClick={async () => {
                                    if (confirm(`Are you sure you want to delete this ${method.type} 2FA method?`)) {
                                      setError(null);
                                      setSuccess(null);
                                      setIsLoading(true);
                                      try {
                                        await request('/api/idm/profile/2fa/delete', {
                                          method: 'POST',
                                          headers: {
                                            'Content-Type': 'application/json',
                                          },
                                          body: JSON.stringify({
                                            twofa_type: method.type,
                                            twofa_id: method.two_factor_id
                                          })
                                        });
                                        setSuccess(`${method.type} 2FA method deleted successfully`);
                                        fetch2FAMethods();
                                      } catch (err) {
                                        const errorDetails = extractErrorDetails(err);
                                        setError(errorDetails.message || `Failed to delete ${method.type} 2FA method`);
                                      } finally {
                                        setIsLoading(false);
                                      }
                                    }
                                  }}
                                  class="px-3 py-1 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                                >
                                  <div class="flex items-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                    </svg>
                                    Delete
                                  </div>
                                </button>
                              </div>
                            </div>
                          )}
                        </For>
                      </div>
                      
                      <Show when={!isAddingMethod()}>
                        <div class="mt-4 flex justify-end">
                          <button
                            onClick={() => setIsAddingMethod(true)}
                            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                          >
                            Add 2FA Method
                          </button>
                        </div>
                      </Show>
                    </div>
                  </Show>
                  
                  <Show when={!isLoadingMethods() && twoFactorMethods().length === 0 && !isAddingMethod()}>
                    <div class="py-4 border rounded-md text-center">
                      <p class="text-sm text-gray-500 mb-4">You don't have any 2FA methods set up yet.</p>
                      
                      <div class="flex justify-center">
                        <button
                          onClick={() => setIsAddingMethod(true)}
                          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        >
                          Add 2FA Method
                        </button>
                      </div>
                    </div>
                  </Show>
                </div>

              {/* QR code section removed as TOTP is not supported */}

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

              {/* Removed the "Enter Code to Disable 2FA" block as requested */}
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="devices">
        <Card>
          <CardHeader>
            <CardTitle>Linked Devices</CardTitle>
          </CardHeader>
          <CardContent>
            {deviceError() && (
              <Alert class="mb-4" variant="destructive">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{deviceError()}</AlertDescription>
              </Alert>
            )}
            
            <Show when={isLoadingDevices()}>
              <div class="py-8 text-center">
                <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mb-2"></div>
                <p class="text-sm text-gray-500">Loading your linked devices...</p>
              </div>
            </Show>
            
            <Show when={!isLoadingDevices() && linkedDevices().length === 0}>
              <div class="py-8 border rounded-md text-center bg-gray-50">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mx-auto text-gray-400 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <p class="text-sm text-gray-500 mb-2">You don't have any linked devices.</p>
                <p class="text-xs text-gray-400">Devices are automatically linked when you sign in from a new browser or device.</p>
              </div>
            </Show>
            
            <Show when={!isLoadingDevices() && linkedDevices().length > 0}>
              <div class="overflow-x-auto rounded-md border">
                <table class="min-w-full divide-y divide-gray-200">
                  <thead class="bg-gray-50">
                    <tr>
                      <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Device</th>
                      <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Last Login</th>
                      <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Expires</th>
                      <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                        <span class="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-gray-200 bg-white">
                    <For each={linkedDevices()}>
                      {(device) => (
                        <tr class="hover:bg-gray-50">
                          <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                            <div class="flex flex-col">
                              <div class="flex items-center">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-gray-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                </svg>
                                <Show when={editingDevice() === device.fingerprint}>
                                  <Input
                                    id="device-name"
                                    type="text"
                                    value={newDisplayName()}
                                    onInput={(e) => setNewDisplayName(e.currentTarget.value)}
                                    class="w-full"
                                  />
                                </Show>
                                <Show when={editingDevice() !== device.fingerprint}>
                                  <span class="font-medium">{device.display_name || device.device_name || 'Unknown Device'}</span>
                                  <button
                                    onClick={() => handleEditDevice(device)}
                                    class="ml-2 text-gray-500 hover:text-gray-700"
                                  >
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-1.773-5.94a.5.5 0 011.064.02L4.192 17.854a.5.5 0 01-.642.328v5.205a.5.5 0 01-1.064 0v-7.043a.5.5 0 01.642-.328l3.536-3.536a.5.5 0 01.642 0z" />
                                    </svg>
                                  </button>
                                </Show>
                              </div>
                              <div class="flex items-center mt-1">
                                <span class="text-xs text-gray-500 bg-gray-100 rounded-full px-2 py-1">{device.device_type || 'Other'}</span>
                              </div>
                            </div>
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                            {formatDate(device.last_login)}
                          </td>
                          <td class="whitespace-nowrap px-3 py-4 text-sm">
                            <span class={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${isExpiringSoon(device.expires_at || '') ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                              {formatDate(device.expires_at)}
                            </span>
                          </td>
                          <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                            <Show when={editingDevice() === device.fingerprint}>
                              <button
                                onClick={handleSaveDeviceName}
                                class="inline-flex items-center rounded-md border border-transparent bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                              >
                                Save
                              </button>
                              <button
                                onClick={() => setEditingDevice(null)}
                                class="ml-2 inline-flex items-center rounded-md border border-transparent bg-red-100 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                              >
                                Cancel
                              </button>
                            </Show>
                            <Show when={editingDevice() !== device.fingerprint}>
                              <button
                                onClick={() => handleUnlinkDevice(device.fingerprint)}
                                disabled={isLoading()}
                                class="inline-flex items-center rounded-md border border-transparent bg-red-100 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6" />
                                </svg>
                                {isLoading() ? 'Unlinking...' : 'Unlink'}
                              </button>
                            </Show>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
              <div class="mt-4 bg-blue-50 p-4 rounded-md">
                <div class="flex">
                  <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                      <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                    </svg>
                  </div>
                  <div class="ml-3 flex-1">
                    <p class="text-sm text-blue-700">
                      These are devices that have been verified for your account. Devices are automatically unlinked after 90 days for security.
                    </p>
                  </div>
                </div>
              </div>
            </Show>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="accounts">
        <AssociatedAccounts />
      </TabsContent>
    </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
