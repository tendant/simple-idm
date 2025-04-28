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
	device := Device{
		Fingerprint:    fingerprint,
		UserAgent:      "test-user-agent",
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
	}

	// Test creating a new device
	createdDevice, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)
	assert.Equal(t, device.Fingerprint, createdDevice.Fingerprint)
	assert.Equal(t, device.UserAgent, createdDevice.UserAgent)

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
	device := Device{
		Fingerprint:    fingerprint,
		UserAgent:      "test-user-agent",
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Test getting an existing device
	retrievedDevice, err := repo.GetDeviceByFingerprint(ctx, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, device.Fingerprint, retrievedDevice.Fingerprint)
	assert.Equal(t, device.UserAgent, retrievedDevice.UserAgent)

	// Test getting a non-existent device
	_, err = repo.GetDeviceByFingerprint(ctx, "non-existent-fingerprint")
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
			Fingerprint:    "fingerprint-1",
			LastLogin:      now,
			CreatedAt:      now,
			LastModifiedAt: now,
		},
		{
			Fingerprint:    "fingerprint-2",
			UserAgent:      "user-agent-2",
			LastLogin:      now,
			CreatedAt:      now,
			LastModifiedAt: now,
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

func TestInMemDeviceRepository_UpdateDeviceLastLogin(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	initialTime := time.Now().UTC().Add(-24 * time.Hour) // 1 day ago
	device := Device{
		Fingerprint:    fingerprint,
		LastLogin:      initialTime,
		CreatedAt:      initialTime,
		LastModifiedAt: initialTime,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Update the last login time
	newLoginTime := time.Now().UTC()
	updatedDevice, err := repo.UpdateDeviceLastLogin(ctx, fingerprint, newLoginTime)
	require.NoError(t, err)

	// Verify the last login time was updated
	assert.Equal(t, newLoginTime, updatedDevice.LastLogin)
	assert.True(t, updatedDevice.LastModifiedAt.After(initialTime))

	// Test updating a non-existent device
	_, err = repo.UpdateDeviceLastLogin(ctx, "non-existent-fingerprint", newLoginTime)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_LinkLoginToDevice(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint:    fingerprint,
		UserAgent:      "test-user-agent",
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
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
		Fingerprint:    fingerprint,
		UserAgent:      "test-user-agent",
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
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

func TestInMemDeviceRepository_ExtendLoginDeviceExpiry(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	now := time.Now().UTC()
	device := Device{
		Fingerprint:    fingerprint,
		UserAgent:      "test-user-agent",
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
	}

	// Add the device to the repository
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Link a login to the device
	loginID := uuid.New()
	loginDevice, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Extend the expiry date
	originalExpiry := loginDevice.ExpiresAt
	newExpiry := now.Add(365 * 24 * time.Hour) // 1 year from now
	err = repo.ExtendLoginDeviceExpiry(ctx, loginID, fingerprint, newExpiry)
	require.NoError(t, err)

	// Verify the expiry date was extended
	retrievedDevice, _, err := repo.GetLoginDeviceWithExpiry(ctx, loginID, fingerprint)
	require.NoError(t, err)
	assert.True(t, retrievedDevice.ExpiresAt.After(originalExpiry))
	assert.Equal(t, newExpiry, retrievedDevice.ExpiresAt)

	// Test extending a non-existent link
	nonExistentLoginID := uuid.New()
	err = repo.ExtendLoginDeviceExpiry(ctx, nonExistentLoginID, fingerprint, newExpiry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestInMemDeviceRepository_WithTx(t *testing.T) {
	// Setup
	repo := NewInMemDeviceRepository()

	// Test that WithTx returns the repository itself
	txRepo := repo.WithTx(nil)
	assert.Equal(t, repo, txRepo)
}
