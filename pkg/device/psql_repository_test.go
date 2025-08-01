package device

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPostgresDeviceRepository(t *testing.T) *PostgresDeviceRepository {
	connStr := "postgres://idm:pwd@localhost:5432/idm_db"
	dbPool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		t.Fatalf("Failed to connect to the database: %v", err)
	}

	return NewPostgresDeviceRepository(dbPool)
}

func TestPostgresDeviceRepository_CreateDeviceWithDeviceID(t *testing.T) {
	// Skip if running in CI environment or quick tests
	if testing.Short() {
		t.Skip("Skipping PostgreSQL test in short mode")
	}

	repo := setupPostgresDeviceRepository(t)
	ctx := context.Background()

	// Generate a unique fingerprint for this test
	testFingerprint := "test_fingerprint_" + uuid.New().String()
	deviceID := uuid.New().String()

	// Create a device with a device_id
	device := Device{
		Fingerprint:      testFingerprint,
		UserAgent:        "Test User Agent",
		AcceptHeaders:    "Test Accept Headers",
		Timezone:         "UTC",
		ScreenResolution: "1920x1080",
		DeviceName:       "Test Device",
		DeviceType:       DeviceTypeMobile,
		DeviceID:         deviceID,
	}

	// Save the device
	createdDevice, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Verify the device was created with the correct device_id
	assert.Equal(t, testFingerprint, createdDevice.Fingerprint)
	assert.Equal(t, deviceID, createdDevice.DeviceID)

	// Retrieve the device to verify it was stored correctly
	retrievedDevice, err := repo.GetDeviceByFingerprint(ctx, testFingerprint)
	require.NoError(t, err)

	// Verify the device_id was stored and retrieved correctly
	assert.Equal(t, deviceID, retrievedDevice.DeviceID)

	// Clean up - this is important to avoid test pollution
	// Note: In a real test environment, you might want to use transactions that are rolled back
	// instead of deleting data, but for this example we'll delete the test device
	_, _ = repo.db.Exec(ctx, "DELETE FROM device WHERE fingerprint = $1", testFingerprint)
}

func TestPostgresDeviceRepository_CreateDeviceWithoutDeviceID(t *testing.T) {
	// Skip if running in CI environment or quick tests
	if testing.Short() {
		t.Skip("Skipping PostgreSQL test in short mode")
	}

	repo := setupPostgresDeviceRepository(t)
	ctx := context.Background()

	// Generate a unique fingerprint for this test
	testFingerprint := "test_fingerprint_" + uuid.New().String()

	// Create a device without a device_id
	device := Device{
		Fingerprint:      testFingerprint,
		UserAgent:        "Test User Agent",
		AcceptHeaders:    "Test Accept Headers",
		Timezone:         "UTC",
		ScreenResolution: "1920x1080",
		DeviceName:       "Test Device",
		DeviceType:       DeviceTypeDesktop,
	}

	// Save the device
	createdDevice, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Verify the device was created with a nil device_id
	assert.Equal(t, testFingerprint, createdDevice.Fingerprint)
	assert.Empty(t, createdDevice.DeviceID)

	// Retrieve the device to verify it was stored correctly
	retrievedDevice, err := repo.GetDeviceByFingerprint(ctx, testFingerprint)
	require.NoError(t, err)

	// Verify the device_id is nil
	assert.Empty(t, retrievedDevice.DeviceID)

	// Clean up
	_, _ = repo.db.Exec(ctx, "DELETE FROM device WHERE fingerprint = $1", testFingerprint)
}

func TestPostgresDeviceRepository_FindDevicesByLogin(t *testing.T) {
	// Skip if running in CI environment or quick tests
	if testing.Short() {
		t.Skip("Skipping PostgreSQL test in short mode")
	}

	repo := setupPostgresDeviceRepository(t)
	ctx := context.Background()

	// Generate a unique fingerprint and login ID for this test
	testFingerprint := "test_fingerprint_" + uuid.New().String()
	loginID := uuid.MustParse("e36d828b-a400-4eaa-89d4-dd027038af2e")
	deviceID := uuid.New().String()

	// Create a device with a device_id
	device := Device{
		Fingerprint:      testFingerprint,
		UserAgent:        "Test User Agent",
		AcceptHeaders:    "Test Accept Headers",
		Timezone:         "UTC",
		ScreenResolution: "1920x1080",
		DeviceName:       "Test Device",
		DeviceType:       DeviceTypeMobile,
		DeviceID:         deviceID,
	}

	// Save the device
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Link the device to a login
	_, err = repo.LinkLoginToDevice(ctx, loginID, testFingerprint)
	require.NoError(t, err)

	// Find devices by login
	devices, err := repo.FindDevicesByLogin(ctx, loginID)
	require.NoError(t, err)

	// Verify the device was found and has the correct device_id
	found := false
	for _, d := range devices {
		if d.Fingerprint == testFingerprint {
			assert.Equal(t, deviceID, d.DeviceID)
			found = true
			break
		}
	}
	assert.True(t, found, "Device with fingerprint %s not found in devices linked to login", testFingerprint)

	// Clean up
	_, _ = repo.db.Exec(ctx, "DELETE FROM login_device WHERE fingerprint = $1", testFingerprint)
	_, _ = repo.db.Exec(ctx, "DELETE FROM device WHERE fingerprint = $1", testFingerprint)
}

func TestPostgresDeviceRepository_UpdateDeviceLastLogin(t *testing.T) {
	// Skip if running in CI environment or quick tests
	if testing.Short() {
		t.Skip("Skipping PostgreSQL test in short mode")
	}

	repo := setupPostgresDeviceRepository(t)
	ctx := context.Background()

	// Generate a unique fingerprint for this test
	testFingerprint := "test_fingerprint_" + uuid.New().String()
	deviceID := uuid.New().String()

	// Create a device with a device_id
	device := Device{
		Fingerprint:      testFingerprint,
		UserAgent:        "Test User Agent",
		AcceptHeaders:    "Test Accept Headers",
		Timezone:         "UTC",
		ScreenResolution: "1920x1080",
		DeviceName:       "Test Device",
		DeviceType:       DeviceTypeMobile,
		DeviceID:         deviceID,
		LastLoginAt:      time.Now().UTC().Add(-24 * time.Hour), // Set last login to yesterday
	}

	// Save the device
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	// Update the last login time
	newLastLogin := time.Now().UTC()
	updatedDevice, err := repo.UpdateDeviceLastLogin(ctx, testFingerprint, newLastLogin)
	require.NoError(t, err)

	// Verify the device was updated but device_id is preserved
	assert.Equal(t, deviceID, updatedDevice.DeviceID)
	assert.WithinDuration(t, newLastLogin, updatedDevice.LastLoginAt, time.Second)

	// Clean up
	_, _ = repo.db.Exec(ctx, "DELETE FROM device WHERE fingerprint = $1", testFingerprint)
}
