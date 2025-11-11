package device

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDeviceService(t *testing.T) *DeviceService {
	// Create repository with default options
	repo := NewInMemDeviceRepositoryWithOptions(DefaultDeviceRepositoryOptions())

	// BREAKING CHANGE (2025-11): Removed unused loginRepository parameter
	// The device service no longer depends on login package, eliminating circular dependency
	service := NewDeviceService(repo)
	return service
}

// Test for DeviceService using in-memory repository
func TestDeviceService_RegisterDevice(t *testing.T) {
	// Setup
	service := setupDeviceService(t)
	ctx := context.Background()

	// Test data
	fingerprint := "test-fingerprint"
	fingerprintData := FingerprintData{
		UserAgent:        "test-user-agent",
		AcceptHeaders:    "test-accept-headers",
		Timezone:         "UTC+0",
		ScreenResolution: "1920x1080",
	}

	// Test registering a new device
	device, err := service.RegisterDevice(ctx, fingerprint, fingerprintData)
	require.NoError(t, err)
	assert.Equal(t, fingerprint, device.Fingerprint)
	assert.Equal(t, fingerprintData.UserAgent, device.UserAgent)
	assert.Equal(t, fingerprintData.AcceptHeaders, device.AcceptHeaders)
	assert.Equal(t, fingerprintData.Timezone, device.Timezone)
	assert.Equal(t, fingerprintData.ScreenResolution, device.ScreenResolution)
	assert.NotEmpty(t, device.AcceptHeaders)
	assert.NotEmpty(t, device.Timezone)
	assert.NotEmpty(t, device.ScreenResolution)

	// Test registering the same device again (should update last login)
	initialLastLogin := device.LastLoginAt
	time.Sleep(10 * time.Millisecond) // Ensure time difference
	updatedDevice, err := service.RegisterDevice(ctx, fingerprint, fingerprintData)
	require.NoError(t, err)
	assert.Equal(t, fingerprint, updatedDevice.Fingerprint)
	assert.True(t, updatedDevice.LastLoginAt.After(initialLastLogin))
}

func TestDeviceService_LinkDeviceToLogin(t *testing.T) {
	// Setup
	service := setupDeviceService(t)
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	fingerprintData := FingerprintData{
		UserAgent: "test-user-agent",
	}
	_, err := service.RegisterDevice(ctx, fingerprint, fingerprintData)
	require.NoError(t, err)

	// Test linking a device to a login
	loginID := uuid.New()
	err = service.LinkDeviceToLogin(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link was created by finding the device
	devices, err := service.FindDevicesByLogin(ctx, loginID)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, fingerprint, devices[0].Fingerprint)

	// Test linking a non-existent device
	nonExistentFingerprint := "non-existent-fingerprint"
	err = service.LinkDeviceToLogin(ctx, loginID, nonExistentFingerprint)
	assert.Error(t, err)
}

func TestDeviceService_UnlinkLoginFromDevice(t *testing.T) {
	// Setup
	service := setupDeviceService(t)
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	fingerprintData := FingerprintData{
		UserAgent: "test-user-agent",
	}
	_, err := service.RegisterDevice(ctx, fingerprint, fingerprintData)
	require.NoError(t, err)

	// Link a device to a login
	loginID := uuid.New()
	err = service.LinkDeviceToLogin(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link was created
	devices, err := service.FindDevicesByLogin(ctx, loginID)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Unlink the device
	err = service.UnlinkLoginFromDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Verify the link was removed
	devices, err = service.FindDevicesByLogin(ctx, loginID)
	require.NoError(t, err)
	assert.Len(t, devices, 0)

	// Test unlinking a non-existent link
	nonExistentLoginID := uuid.New()
	err = service.UnlinkLoginFromDevice(ctx, nonExistentLoginID, fingerprint)
	assert.Error(t, err)
}

func TestDeviceService_FindDevicesByLogin(t *testing.T) {
	// Setup
	service := setupDeviceService(t)
	ctx := context.Background()

	// Create test devices
	fingerprint1 := "fingerprint-1"
	fingerprint2 := "fingerprint-2"
	fingerprintData1 := FingerprintData{
		UserAgent: "user-agent-1",
	}
	fingerprintData2 := FingerprintData{
		UserAgent: "user-agent-2",
	}

	_, err := service.RegisterDevice(ctx, fingerprint1, fingerprintData1)
	require.NoError(t, err)
	_, err = service.RegisterDevice(ctx, fingerprint2, fingerprintData2)
	require.NoError(t, err)

	// Link devices to logins
	loginID1 := uuid.New()
	loginID2 := uuid.New()

	err = service.LinkDeviceToLogin(ctx, loginID1, fingerprint1)
	require.NoError(t, err)
	err = service.LinkDeviceToLogin(ctx, loginID1, fingerprint2)
	require.NoError(t, err)
	err = service.LinkDeviceToLogin(ctx, loginID2, fingerprint2)
	require.NoError(t, err)

	// Test finding devices by login
	devices, err := service.FindDevicesByLogin(ctx, loginID1)
	require.NoError(t, err)
	assert.Len(t, devices, 2)

	devices, err = service.FindDevicesByLogin(ctx, loginID2)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, fingerprint2, devices[0].Fingerprint)

	// Test finding devices for a login with no linked devices
	nonExistentLoginID := uuid.New()
	devices, err = service.FindDevicesByLogin(ctx, nonExistentLoginID)
	require.NoError(t, err)
	assert.Len(t, devices, 0)

	// Test that unlinked devices are not returned
	err = service.UnlinkLoginFromDevice(ctx, loginID1, fingerprint1)
	require.NoError(t, err)

	devices, err = service.FindDevicesByLogin(ctx, loginID1)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, fingerprint2, devices[0].Fingerprint)
}

func TestDeviceService_GetDeviceByFingerprint(t *testing.T) {
	// Setup
	service := setupDeviceService(t)
	ctx := context.Background()

	// Create a test device
	fingerprint := "test-fingerprint"
	fingerprintData := FingerprintData{
		UserAgent:        "test-user-agent",
		AcceptHeaders:    "test-accept-headers",
		Timezone:         "UTC+0",
		ScreenResolution: "1920x1080",
	}
	device, err := service.RegisterDevice(ctx, fingerprint, fingerprintData)
	require.NoError(t, err)

	// Test getting the device by fingerprint
	retrievedDevice, err := service.GetDeviceByFingerprint(ctx, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, device.Fingerprint, retrievedDevice.Fingerprint)
	assert.Equal(t, device.UserAgent, retrievedDevice.UserAgent)
	assert.Equal(t, device.AcceptHeaders, retrievedDevice.AcceptHeaders)
	assert.Equal(t, device.Timezone, retrievedDevice.Timezone)
	assert.Equal(t, device.ScreenResolution, retrievedDevice.ScreenResolution)

	// Test getting a non-existent device
	_, err = service.GetDeviceByFingerprint(ctx, "non-existent-fingerprint")
	assert.Error(t, err)
}
