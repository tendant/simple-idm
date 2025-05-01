package device

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemDeviceRepository_CreateDevice(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	acceptHeaders := "accept-headers"
	timezone := "UTC+0"
	screenResolution := "1920x1080"
	
	device := Device{
		Fingerprint:      fingerprint,
		UserAgent:        "test-user-agent",
		AcceptHeaders:    acceptHeaders,
		Timezone:         timezone,
		ScreenResolution: screenResolution,
		LastLoginAt:      now,
		CreatedAt:        now,
	}

	// Test creating a new device
	createdDevice, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)
	assert.Equal(t, device.Fingerprint, createdDevice.Fingerprint)
	assert.Equal(t, device.UserAgent, createdDevice.UserAgent)
	assert.Equal(t, device.AcceptHeaders, createdDevice.AcceptHeaders)
	assert.Equal(t, device.Timezone, createdDevice.Timezone)
	assert.Equal(t, device.ScreenResolution, createdDevice.ScreenResolution)

	// Test creating a device with the same fingerprint (should fail)
	_, err = repo.CreateDevice(ctx, device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestInMemDeviceRepository_GetDeviceByFingerprint(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	acceptHeaders := "accept-headers"
	timezone := "UTC+0"
	screenResolution := "1920x1080"
	
	device := Device{
		Fingerprint:      fingerprint,
		UserAgent:        "test-user-agent",
		AcceptHeaders:    acceptHeaders,
		Timezone:         timezone,
		ScreenResolution: screenResolution,
		LastLoginAt:      now,
		CreatedAt:        now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Test getting an existing device
	retrievedDevice, err := repo.GetDeviceByFingerprint(ctx, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, device.Fingerprint, retrievedDevice.Fingerprint)
	assert.Equal(t, device.UserAgent, retrievedDevice.UserAgent)
	assert.Equal(t, device.AcceptHeaders, retrievedDevice.AcceptHeaders)
	assert.Equal(t, device.Timezone, retrievedDevice.Timezone)
	assert.Equal(t, device.ScreenResolution, retrievedDevice.ScreenResolution)

	// Test getting a non-existent device
	_, err = repo.GetDeviceByFingerprint(ctx, "non-existent-fingerprint")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_UpdateDeviceLastLogin(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	initialTime := time.Now().UTC().Add(-24 * time.Hour) // 1 day ago
	acceptHeaders := "accept-headers"
	timezone := "UTC+0"
	screenResolution := "1920x1080"
	
	device := Device{
		Fingerprint:      fingerprint,
		UserAgent:        "test-user-agent",
		AcceptHeaders:    acceptHeaders,
		Timezone:         timezone,
		ScreenResolution: screenResolution,
		LastLoginAt:      initialTime,
		CreatedAt:        initialTime,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Update the last login time
	newLoginTime := time.Now().UTC()
	updatedDevice, err := repo.UpdateDeviceLastLogin(ctx, fingerprint, newLoginTime)
	require.NoError(t, err)

	// Verify the last login time was updated
	assert.Equal(t, newLoginTime, updatedDevice.LastLoginAt)
	// Verify other fields remain unchanged
	assert.Equal(t, device.UserAgent, updatedDevice.UserAgent)
	assert.Equal(t, device.AcceptHeaders, updatedDevice.AcceptHeaders)

	// Test updating a non-existent device
	_, err = repo.UpdateDeviceLastLogin(ctx, "non-existent-fingerprint", newLoginTime)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_FindDevices(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create test devices
	now := time.Now().UTC()
	devices := []Device{
		{
			Fingerprint: "fingerprint-1",
			UserAgent:   "user-agent-1",
			AcceptHeaders: "accept-headers-1",
			Timezone:     "UTC+0",
			LastLoginAt:  now,
			CreatedAt:    now,
		},
		{
			Fingerprint: "fingerprint-2",
			UserAgent:   "user-agent-2",
			AcceptHeaders: "accept-headers-2",
			ScreenResolution: "1920x1080",
			LastLoginAt:      now,
			CreatedAt:        now,
		},
	}

	// Add devices to the repository
	for _, device := range devices {
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)
	}

	// Test finding all devices
	foundDevices, err := repo.FindDevices(ctx)
	require.NoError(t, err)
	assert.Len(t, foundDevices, len(devices))

	// Verify all devices are found
	fingerprintMap := make(map[string]bool)
	for _, device := range foundDevices {
		fingerprintMap[device.Fingerprint] = true
	}
	for _, device := range devices {
		assert.True(t, fingerprintMap[device.Fingerprint], "Device with fingerprint %s not found", device.Fingerprint)
	}
}

func TestInMemDeviceRepository_LinkLoginToDevice(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint: fingerprint,
		UserAgent:   "test-user-agent",
		LastLoginAt: now,
		CreatedAt:   now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Link a login to the device
	loginID := uuid.New()
	loginDevice, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link was created
	assert.Equal(t, loginID, loginDevice.LoginID)
	assert.Equal(t, fingerprint, loginDevice.Fingerprint)
	assert.False(t, loginDevice.ExpiresAt.Before(now))

	// Test linking to a non-existent device
	_, err = repo.LinkLoginToDevice(ctx, loginID, "non-existent-fingerprint")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test updating an existing link
	oldExpiryDate := loginDevice.ExpiresAt
	time.Sleep(10 * time.Millisecond) // Ensure time difference

	updatedLoginDevice, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)
	assert.True(t, updatedLoginDevice.ExpiresAt.After(oldExpiryDate) ||
		updatedLoginDevice.ExpiresAt.Equal(oldExpiryDate))
}

func TestInMemDeviceRepository_GetLoginDeviceWithExpiry(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint: fingerprint,
		UserAgent:   "test-user-agent",
		LastLoginAt: now,
		CreatedAt:   now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Create login IDs
	loginID := uuid.New()

	// Link with future expiry (not expired)
	futureExpiry := now.Add(24 * time.Hour)
	loginDevice := LoginDevice{
		ID:          uuid.New(),
		LoginID:     loginID,
		Fingerprint: fingerprint,
		LinkedAt:    now,
		ExpiresAt:   futureExpiry,
	}

	// Manually add to repository
	key := loginID.String() + ":" + fingerprint
	repo.loginDevices[key] = loginDevice

	// Test getting a non-expired link
	retrievedDevice, isExpired, err := repo.GetLoginDeviceWithExpiry(ctx, loginID, fingerprint)
	require.NoError(t, err)
	assert.False(t, isExpired)
	assert.Equal(t, loginID, retrievedDevice.LoginID)
	assert.Equal(t, fingerprint, retrievedDevice.Fingerprint)

	// Link with past expiry (expired)
	expiredLoginID := uuid.New()
	pastExpiry := now.Add(-24 * time.Hour)
	expiredLoginDevice := LoginDevice{
		ID:          uuid.New(),
		LoginID:     expiredLoginID,
		Fingerprint: fingerprint,
		LinkedAt:    now.Add(-48 * time.Hour),
		ExpiresAt:   pastExpiry,
	}

	// Manually add to repository
	expiredKey := expiredLoginID.String() + ":" + fingerprint
	repo.loginDevices[expiredKey] = expiredLoginDevice

	// Test getting an expired link
	retrievedExpiredDevice, isExpired, err := repo.GetLoginDeviceWithExpiry(ctx, expiredLoginID, fingerprint)
	require.NoError(t, err)
	assert.True(t, isExpired)
	assert.Equal(t, expiredLoginID, retrievedExpiredDevice.LoginID)

	// Test getting a non-existent link
	nonExistentLoginID := uuid.New()
	_, _, err = repo.GetLoginDeviceWithExpiry(ctx, nonExistentLoginID, fingerprint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_FindDevicesByLogin(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create test devices
	now := time.Now().UTC()
	device1 := Device{
		Fingerprint: "fingerprint-1",
		UserAgent:   "user-agent-1",
		LastLoginAt: now,
		CreatedAt:   now,
	}
	device2 := Device{
		Fingerprint: "fingerprint-2",
		UserAgent:   "user-agent-2",
		LastLoginAt: now,
		CreatedAt:   now,
	}

	// Add devices to the repository
	_, err := repo.CreateDevice(ctx, device1)
	require.NoError(t, err)
	_, err = repo.CreateDevice(ctx, device2)
	require.NoError(t, err)

	// Create login IDs
	loginID1 := uuid.New()
	loginID2 := uuid.New()

	// Link devices to logins
	_, err = repo.LinkLoginToDevice(ctx, loginID1, device1.Fingerprint)
	require.NoError(t, err)
	_, err = repo.LinkLoginToDevice(ctx, loginID1, device2.Fingerprint)
	require.NoError(t, err)
	_, err = repo.LinkLoginToDevice(ctx, loginID2, device2.Fingerprint)
	require.NoError(t, err)

	// Test finding devices by login
	devices, err := repo.FindDevicesByLogin(ctx, loginID1)
	require.NoError(t, err)
	assert.Len(t, devices, 2)

	devices, err = repo.FindDevicesByLogin(ctx, loginID2)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, device2.Fingerprint, devices[0].Fingerprint)

	// Test finding devices for a login with no linked devices
	nonExistentLoginID := uuid.New()
	devices, err = repo.FindDevicesByLogin(ctx, nonExistentLoginID)
	require.NoError(t, err)
	assert.Len(t, devices, 0)

	// Test that unlinked (deleted) devices are not returned
	err = repo.UnlinkLoginToDevice(ctx, loginID1, device1.Fingerprint)
	require.NoError(t, err)

	devices, err = repo.FindDevicesByLogin(ctx, loginID1)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, device2.Fingerprint, devices[0].Fingerprint)
}

func TestInMemDeviceRepository_UnlinkLoginToDevice(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint: fingerprint,
		UserAgent:   "test-user-agent",
		LastLoginAt: now,
		CreatedAt:   now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Link a login to the device
	loginID := uuid.New()
	_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link exists
	loginDevice, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	require.NoError(t, err)
	assert.NotNil(t, loginDevice)
	assert.Nil(t, loginDevice.DeletedAt)

	// Unlink the device
	err = repo.UnlinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link is marked as deleted
	loginDevice, err = repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	assert.Error(t, err)
	assert.Nil(t, loginDevice)
	assert.Contains(t, err.Error(), "not found")

	// Test unlinking a non-existent link
	nonExistentLoginID := uuid.New()
	err = repo.UnlinkLoginToDevice(ctx, nonExistentLoginID, fingerprint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_FindLoginDeviceByFingerprintAndLoginID(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint: fingerprint,
		UserAgent:   "test-user-agent",
		LastLoginAt: now,
		CreatedAt:   now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Link a login to the device
	loginID := uuid.New()
	_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Test finding an existing link
	loginDevice, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	require.NoError(t, err)
	assert.NotNil(t, loginDevice)
	assert.Equal(t, loginID, loginDevice.LoginID)
	assert.Equal(t, fingerprint, loginDevice.Fingerprint)

	// Test finding a non-existent link
	nonExistentLoginID := uuid.New()
	loginDevice, err = repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, nonExistentLoginID)
	assert.Error(t, err)
	assert.Nil(t, loginDevice)

	// Test that deleted links are not found
	err = repo.UnlinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	loginDevice, err = repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	assert.Error(t, err)
	assert.Nil(t, loginDevice)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_WithTx(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()

	// Test that WithTx returns the repository itself
	txRepo := repo.WithTx(nil)
	assert.Equal(t, repo, txRepo)
}
