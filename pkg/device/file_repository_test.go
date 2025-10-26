package device

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRepo creates a temporary directory and repository for testing
func setupTestRepo(t *testing.T) (*FileDeviceRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "device-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	options := DefaultDeviceRepositoryOptions()
	repo, err := NewFileDeviceRepository(tempDir, options)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

// createTestDevice creates a test device
func createTestDevice(fingerprint string) Device {
	return Device{
		Fingerprint:      fingerprint,
		UserAgent:        "Test User Agent",
		AcceptHeaders:    "application/json",
		Timezone:         "America/New_York",
		ScreenResolution: "1920x1080",
		DeviceName:       "Test Device",
		DeviceType:       "Desktop",
		DeviceID:         fingerprint,
	}
}

func TestFileDeviceRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "device-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	options := DefaultDeviceRepositoryOptions()

	// Should create directory if it doesn't exist
	repo, err := NewFileDeviceRepository(tempDir, options)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
	assert.Equal(t, DefaultDeviceExpiryDuration, repo.expiryDuration)
}

func TestFileDeviceRepository_CreateDevice(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)

	t.Run("Success", func(t *testing.T) {
		before := time.Now().UTC()
		createdDevice, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)
		after := time.Now().UTC()

		assert.Equal(t, fingerprint, createdDevice.Fingerprint)
		assert.True(t, createdDevice.CreatedAt.After(before) || createdDevice.CreatedAt.Equal(before))
		assert.True(t, createdDevice.CreatedAt.Before(after) || createdDevice.CreatedAt.Equal(after))
		assert.Equal(t, createdDevice.CreatedAt, createdDevice.LastLoginAt)
	})

	t.Run("DuplicateDevice", func(t *testing.T) {
		// Try to create device with same fingerprint
		_, err := repo.CreateDevice(ctx, device)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device already exists")
	})
}

func TestFileDeviceRepository_GetDeviceByFingerprint(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)

	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		foundDevice, err := repo.GetDeviceByFingerprint(ctx, fingerprint)
		require.NoError(t, err)
		assert.Equal(t, fingerprint, foundDevice.Fingerprint)
		assert.Equal(t, device.UserAgent, foundDevice.UserAgent)
	})

	t.Run("DeviceNotFound", func(t *testing.T) {
		_, err := repo.GetDeviceByFingerprint(ctx, "nonexistent_fingerprint")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device not found")
	})
}

func TestFileDeviceRepository_FindDevices(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Create multiple devices
	for i := 0; i < 3; i++ {
		fingerprint := "fingerprint_" + string(rune(i))
		device := createTestDevice(fingerprint)
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)
	}

	t.Run("FindAll", func(t *testing.T) {
		devices, err := repo.FindDevices(ctx)
		require.NoError(t, err)
		assert.Len(t, devices, 3)
	})
}

func TestFileDeviceRepository_UpdateDeviceLastLogin(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)

	createdDevice, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		newLastLogin := time.Now().UTC().Add(1 * time.Hour)
		updatedDevice, err := repo.UpdateDeviceLastLogin(ctx, fingerprint, newLastLogin)
		require.NoError(t, err)
		assert.Equal(t, newLastLogin, updatedDevice.LastLoginAt)
		assert.NotEqual(t, createdDevice.LastLoginAt, updatedDevice.LastLoginAt)
	})

	t.Run("DeviceNotFound", func(t *testing.T) {
		_, err := repo.UpdateDeviceLastLogin(ctx, "nonexistent", time.Now().UTC())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device not found")
	})
}

func TestFileDeviceRepository_LinkLoginToDevice(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	loginID := uuid.New()

	t.Run("CreateNewLink", func(t *testing.T) {
		before := time.Now().UTC()
		loginDevice, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
		require.NoError(t, err)
		after := time.Now().UTC()

		assert.NotEqual(t, uuid.Nil, loginDevice.ID)
		assert.Equal(t, loginID, loginDevice.LoginID)
		assert.Equal(t, fingerprint, loginDevice.Fingerprint)
		assert.True(t, loginDevice.LinkedAt.After(before) || loginDevice.LinkedAt.Equal(before))
		assert.True(t, loginDevice.LinkedAt.Before(after) || loginDevice.LinkedAt.Equal(after))
		assert.True(t, loginDevice.ExpiresAt.After(time.Now().UTC()))
	})

	t.Run("UpdateExistingLink", func(t *testing.T) {
		// Link again to update expiry
		firstLink, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		updatedLink, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
		require.NoError(t, err)

		assert.Equal(t, firstLink.ID, updatedLink.ID)
		assert.True(t, updatedLink.UpdatedAt.After(firstLink.UpdatedAt))
	})
}

func TestFileDeviceRepository_FindLoginDeviceByFingerprintAndLoginID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	loginID := uuid.New()

	t.Run("LinkNotFound", func(t *testing.T) {
		_, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device not found")
	})

	t.Run("Success", func(t *testing.T) {
		// Create link
		_, err := repo.LinkLoginToDevice(ctx, loginID, fingerprint)
		require.NoError(t, err)

		// Find it
		loginDevice, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		require.NoError(t, err)
		assert.Equal(t, loginID, loginDevice.LoginID)
		assert.Equal(t, fingerprint, loginDevice.Fingerprint)
	})
}

func TestFileDeviceRepository_FindDevicesByLogin(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create 3 devices and link them to the login
	fingerprints := []string{"fp1", "fp2", "fp3"}
	for _, fp := range fingerprints {
		device := createTestDevice(fp)
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)

		_, err = repo.LinkLoginToDevice(ctx, loginID, fp)
		require.NoError(t, err)
	}

	t.Run("FindMultipleDevices", func(t *testing.T) {
		devices, err := repo.FindDevicesByLogin(ctx, loginID)
		require.NoError(t, err)
		assert.Len(t, devices, 3)
	})

	t.Run("NoDevices", func(t *testing.T) {
		devices, err := repo.FindDevicesByLogin(ctx, uuid.New())
		require.NoError(t, err)
		assert.Empty(t, devices)
	})

	t.Run("ExpiredLinksNotReturned", func(t *testing.T) {
		// Create a device with expired link
		expiredFP := "expired_fp"
		expiredDevice := createTestDevice(expiredFP)
		_, err := repo.CreateDevice(ctx, expiredDevice)
		require.NoError(t, err)

		// Manually create expired link
		now := time.Now().UTC()
		expiredLink := &LoginDevice{
			ID:          uuid.New(),
			LoginID:     loginID,
			Fingerprint: expiredFP,
			LinkedAt:    now.Add(-2 * DefaultDeviceExpiryDuration),
			ExpiresAt:   now.Add(-1 * time.Hour), // Already expired
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		repo.mutex.Lock()
		key := repo.makeKey(loginID, expiredFP)
		repo.loginDevices[key] = expiredLink
		repo.mutex.Unlock()

		// Should not include expired device
		devices, err := repo.FindDevicesByLogin(ctx, loginID)
		require.NoError(t, err)
		assert.Len(t, devices, 3) // Only the 3 non-expired devices
	})
}

func TestFileDeviceRepository_ExtendLoginDeviceExpiry(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	loginID := uuid.New()
	_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		originalLink, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		err = repo.ExtendLoginDeviceExpiry(ctx, loginID, fingerprint)
		require.NoError(t, err)

		extendedLink, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		require.NoError(t, err)

		assert.True(t, extendedLink.ExpiresAt.After(originalLink.ExpiresAt))
		assert.True(t, extendedLink.UpdatedAt.After(originalLink.UpdatedAt))
	})

	t.Run("LinkNotFound", func(t *testing.T) {
		err := repo.ExtendLoginDeviceExpiry(ctx, uuid.New(), fingerprint)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device link not found")
	})
}

func TestFileDeviceRepository_UnlinkLoginToDevice(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	loginID := uuid.New()
	_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.UnlinkLoginToDevice(ctx, loginID, fingerprint)
		require.NoError(t, err)

		// Link should no longer exist
		_, err = repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		assert.Error(t, err)
	})

	t.Run("LinkNotFound", func(t *testing.T) {
		err := repo.UnlinkLoginToDevice(ctx, uuid.New(), fingerprint)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device link not found")
	})
}

func TestFileDeviceRepository_UpdateLoginDeviceDisplayName(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	fingerprint := "test_fingerprint_123"
	device := createTestDevice(fingerprint)
	_, err := repo.CreateDevice(ctx, device)
	require.NoError(t, err)

	loginID := uuid.New()
	_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		displayName := "My Laptop"
		updatedLink, err := repo.UpdateLoginDeviceDisplayName(ctx, loginID, fingerprint, displayName)
		require.NoError(t, err)
		assert.Equal(t, displayName, updatedLink.DisplayName)

		// Verify via find
		foundLink, err := repo.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
		require.NoError(t, err)
		assert.Equal(t, displayName, foundLink.DisplayName)
	})

	t.Run("LinkNotFound", func(t *testing.T) {
		_, err := repo.UpdateLoginDeviceDisplayName(ctx, uuid.New(), fingerprint, "Name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device link not found")
	})
}

func TestFileDeviceRepository_GetExpiryDuration(t *testing.T) {
	repo, _ := setupTestRepo(t)

	duration := repo.GetExpiryDuration()
	assert.Equal(t, DefaultDeviceExpiryDuration, duration)
}

func TestFileDeviceRepository_WithTx(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// File-based repo returns self
	txRepo := repo.WithTx(nil)
	assert.Equal(t, repo, txRepo)
}

func TestFileDeviceRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "device-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	fingerprint := "persist_fingerprint"
	loginID := uuid.New()

	options := DefaultDeviceRepositoryOptions()

	// Create repository and add data
	repo1, err := NewFileDeviceRepository(tempDir, options)
	require.NoError(t, err)

	device := createTestDevice(fingerprint)
	_, err = repo1.CreateDevice(ctx, device)
	require.NoError(t, err)

	_, err = repo1.LinkLoginToDevice(ctx, loginID, fingerprint)
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileDeviceRepository(tempDir, options)
	require.NoError(t, err)

	// Data should be loaded
	foundDevice, err := repo2.GetDeviceByFingerprint(ctx, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, fingerprint, foundDevice.Fingerprint)

	loginDevice, err := repo2.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	require.NoError(t, err)
	assert.Equal(t, loginID, loginDevice.LoginID)
}

func TestFileDeviceRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentDeviceCreation", func(t *testing.T) {
		// Concurrent device creations
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				fingerprint := "concurrent_fp_" + string(rune(index))
				device := createTestDevice(fingerprint)
				_, _ = repo.CreateDevice(ctx, device)
			}(i)
		}
		wg.Wait()

		// Verify devices were created
		devices, err := repo.FindDevices(ctx)
		require.NoError(t, err)
		assert.Len(t, devices, numGoroutines)
	})

	t.Run("ConcurrentLinking", func(t *testing.T) {
		fingerprint := "link_test_fp"
		device := createTestDevice(fingerprint)
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)

		// Create multiple logins linking to same device
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				loginID := uuid.New()
				_, _ = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
			}()
		}
		wg.Wait()

		// Verify links were created
		repo.mutex.RLock()
		linkCount := 0
		for _, ld := range repo.loginDevices {
			if ld.Fingerprint == fingerprint {
				linkCount++
			}
		}
		repo.mutex.RUnlock()
		assert.Equal(t, numGoroutines, linkCount)
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		fingerprint := "read_test_fp"
		device := createTestDevice(fingerprint)
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.GetDeviceByFingerprint(ctx, fingerprint)
				if err != nil {
					errors <- err
				}
			}()
		}
		wg.Wait()
		close(errors)

		// No errors should occur
		for err := range errors {
			t.Errorf("Concurrent read error: %v", err)
		}
	})

	t.Run("MixedConcurrentAccess", func(t *testing.T) {
		testFP := "mixed_test_fp"
		testDevice := createTestDevice(testFP)
		_, err := repo.CreateDevice(ctx, testDevice)
		require.NoError(t, err)

		testLoginID := uuid.New()
		_, err = repo.LinkLoginToDevice(ctx, testLoginID, testFP)
		require.NoError(t, err)

		wg.Add(numGoroutines * 2)

		// Writers (update last login)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.UpdateDeviceLastLogin(ctx, testFP, time.Now().UTC())
			}()
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetDeviceByFingerprint(ctx, testFP)
			}()
		}

		wg.Wait()

		// Verify final state exists
		device, err := repo.GetDeviceByFingerprint(ctx, testFP)
		require.NoError(t, err)
		assert.Equal(t, testFP, device.Fingerprint)
	})
}

func TestFileDeviceRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Add multiple devices and links
	for i := 0; i < 3; i++ {
		fingerprint := "device_" + string(rune(i))
		device := createTestDevice(fingerprint)
		_, err := repo.CreateDevice(ctx, device)
		require.NoError(t, err)

		loginID := uuid.New()
		_, err = repo.LinkLoginToDevice(ctx, loginID, fingerprint)
		require.NoError(t, err)
	}

	initialDeviceCount := len(repo.devices)
	initialLinkCount := len(repo.loginDevices)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.devices = make(map[string]*Device)
	repo.loginDevices = make(map[string]*LoginDevice)
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialDeviceCount, len(repo.devices))
	assert.Equal(t, initialLinkCount, len(repo.loginDevices))
}

func TestFileDeviceRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should return appropriate errors/empty results
	_, err := repo.GetDeviceByFingerprint(ctx, "nonexistent")
	assert.Error(t, err)

	devices, err := repo.FindDevices(ctx)
	require.NoError(t, err)
	assert.Empty(t, devices)

	devices, err = repo.FindDevicesByLogin(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, devices)

	_, err = repo.FindLoginDeviceByFingerprintAndLoginID(ctx, "fp", uuid.New())
	assert.Error(t, err)
}
