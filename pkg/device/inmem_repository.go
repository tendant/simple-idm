package device

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InMemDeviceRepository implements DeviceRepository using an in-memory map
type InMemDeviceRepository struct {
	devices      map[string]Device
	loginDevices map[string]LoginDevice
	mu           sync.Mutex
	options      DeviceRepositoryOptions
}

// NewInMemDeviceRepository creates a new in-memory device repository
func NewInMemDeviceRepository() *InMemDeviceRepository {
	return &InMemDeviceRepository{
		devices:      make(map[string]Device),
		loginDevices: make(map[string]LoginDevice),
		options:      DefaultDeviceRepositoryOptions(),
	}
}

// NewInMemDeviceRepositoryWithOptions creates a new in-memory device repository with custom options
func NewInMemDeviceRepositoryWithOptions(options DeviceRepositoryOptions) *InMemDeviceRepository {
	return &InMemDeviceRepository{
		devices:      make(map[string]Device),
		loginDevices: make(map[string]LoginDevice),
		options:      options,
	}
}

// CreateDevice creates a new device in memory
func (r *InMemDeviceRepository) CreateDevice(ctx context.Context, device Device) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if device already exists
	_, err := r.GetDeviceByFingerprint(ctx, device.Fingerprint)
	if err == nil {
		return Device{}, errors.New("device already exists")
	}

	// If DeviceID is empty, generate a new one
	if device.DeviceID == "" {
		device.DeviceID = uuid.New().String()
	}

	// Log if this is a mobile device with a device ID
	if device.DeviceID != "" {
		slog.Info("Creating mobile device with device ID", "fingerprint", device.Fingerprint, "deviceID", device.DeviceID)
	}

	r.devices[device.Fingerprint] = device
	slog.Debug("Device created", "fingerprint", device.Fingerprint)
	return device, nil
}

// GetDeviceByFingerprint retrieves a device by its fingerprint
func (r *InMemDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		slog.Debug("Device not found", "fingerprint", fingerprint)
		return Device{}, errors.New("device not found")
	}

	slog.Debug("Device found", "fingerprint", fingerprint)
	return device, nil
}

// FindDevices returns all devices
func (r *InMemDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	devices := make([]Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	slog.Debug("Found all devices", "deviceCount", len(devices))
	return devices, nil
}

// FindDevicesByLogin returns all devices linked to a specific login
func (r *InMemDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var devices []Device
	// Map to track fingerprints we've already added to avoid duplicates
	fingerprintMap := make(map[string]bool)

	slog.Debug("Finding devices for login", "loginID", loginID)
	deviceCount := 0
	for _, link := range r.loginDevices {
		if link.LoginID == loginID && link.DeletedAt.IsZero() {
			// Only process each fingerprint once
			if _, exists := fingerprintMap[link.Fingerprint]; !exists {
				fingerprintMap[link.Fingerprint] = true

				// Find the device with this fingerprint
				for _, device := range r.devices {
					if device.Fingerprint == link.Fingerprint {
						devices = append(devices, device)
						deviceCount++
						break
					}
				}
			}
		}
	}
	slog.Debug("Found devices for login", "loginID", loginID, "deviceCount", deviceCount)

	return devices, nil
}

// FindLoginsByDevice returns all logins linked to a specific device
func (r *InMemDeviceRepository) FindLoginsByDevice(ctx context.Context, fingerprint string) ([]LoginInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var loginInfos []LoginInfo
	// Map to track login IDs we've already added to avoid duplicates
	loginMap := make(map[uuid.UUID]bool)

	// Find all login devices with this fingerprint
	for _, link := range r.loginDevices {
		if link.Fingerprint == fingerprint {
			// Only process each login once
			if _, exists := loginMap[link.LoginID]; !exists {
				loginMap[link.LoginID] = true

				// For a real implementation, we would query the login service
				// to get the username. For this in-memory implementation,
				// we'll use a placeholder username based on the login ID
				loginInfo := LoginInfo{
					ID:       link.LoginID,
					Username: fmt.Sprintf("user-%s", link.LoginID.String()[:8]),
				}

				loginInfos = append(loginInfos, loginInfo)
			}
		}
	}

	slog.Debug("Found logins for device", "fingerprint", fingerprint, "loginCount", len(loginInfos))
	return loginInfos, nil
}

// UpdateDeviceLastLogin updates the last login time of a device
func (r *InMemDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLoginAt time.Time) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		slog.Debug("Device not found when updating last login", "fingerprint", fingerprint)
		return Device{}, errors.New("device not found")
	}

	device.LastLoginAt = lastLoginAt
	r.devices[fingerprint] = device
	slog.Debug("Device last login updated", "fingerprint", fingerprint, "lastLogin", lastLoginAt)
	return device, nil
}

// LinkLoginToDevice links a login to a device
func (r *InMemDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if device exists
	if _, exists := r.devices[fingerprint]; !exists {
		slog.Debug("Device not found when linking to login", "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, errors.New("device not found")
	}

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	// Check if link already exists
	if existingLink, exists := r.loginDevices[key]; exists && existingLink.DeletedAt.IsZero() {
		// Update the expiry date
		slog.Debug("Updating existing device link", "fingerprint", fingerprint, "loginID", loginID,
			"oldExpiry", existingLink.ExpiresAt.Format(time.RFC3339))
		existingLink.ExpiresAt = CalculateExpiryDate(r.options.ExpiryDuration)
		r.loginDevices[key] = existingLink
		slog.Debug("Device link updated", "fingerprint", fingerprint, "loginID", loginID,
			"newExpiry", existingLink.ExpiresAt.Format(time.RFC3339))
		return existingLink, nil
	}

	// Create new link
	now := time.Now().UTC()
	loginDevice := LoginDevice{
		ID:          uuid.New(),
		LoginID:     loginID,
		Fingerprint: fingerprint,
		DisplayName: r.devices[fingerprint].DeviceName, // Use device_name as initial display_name
		LinkedAt:    now,
		ExpiresAt:   CalculateExpiryDate(r.options.ExpiryDuration),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	slog.Debug("Creating new device link", "fingerprint", fingerprint, "loginID", loginID,
		"expiry", loginDevice.ExpiresAt.Format(time.RFC3339))
	r.loginDevices[key] = loginDevice
	return loginDevice, nil
}

// ExtendLoginDeviceExpiry extends the expiration date of a login device link
func (r *InMemDeviceRepository) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	loginDevice, exists := r.loginDevices[key]
	if !exists || !loginDevice.DeletedAt.IsZero() {
		slog.Debug("Login device link not found or deleted when extending expiry", "fingerprint", fingerprint, "loginID", loginID)
		return errors.New("login device link not found or deleted")
	}
	loginDevice.UpdatedAt = time.Now().UTC()
	loginDevice.LinkedAt = time.Now().UTC()
	loginDevice.ExpiresAt = CalculateExpiryDate(r.options.ExpiryDuration)
	r.loginDevices[key] = loginDevice
	slog.Debug("Login device link expiry extended", "fingerprint", fingerprint, "loginID", loginID,
		"newExpiry", loginDevice.ExpiresAt.Format(time.RFC3339))
	return nil
}

// GetLoginDeviceWithExpiry retrieves a login device link and checks if it's expired
func (r *InMemDeviceRepository) GetLoginDeviceWithExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	loginDevice, exists := r.loginDevices[key]
	if !exists {
		slog.Debug("Login device link not found", "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, false, errors.New("login device link not found")
	}

	// Check if the link is expired
	now := time.Now().UTC()
	isExpired := loginDevice.ExpiresAt.Before(now)

	slog.Debug("Login device link found", "fingerprint", fingerprint, "loginID", loginID,
		"isExpired", isExpired)
	return loginDevice, isExpired, nil
}

// UnlinkLoginToDevice removes the link between a login and a device
func (r *InMemDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	// Check if link exists
	if _, exists := r.loginDevices[key]; !exists {
		slog.Debug("Login device link not found when unlinking", "fingerprint", fingerprint, "loginID", loginID)
		return errors.New("login device link not found")
	}

	// Remove the link
	loginDevice := r.loginDevices[key]
	loginDevice.DeletedAt = time.Now().UTC()
	r.loginDevices[key] = loginDevice
	slog.Debug("Device link marked as deleted", "fingerprint", fingerprint, "loginID", loginID,
		"deletedAt", loginDevice.DeletedAt.Format(time.RFC3339))
	return nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (r *InMemDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	slog.Debug("Finding login device link", "fingerprint", fingerprint, "loginID", loginID)
	for _, link := range r.loginDevices {
		if link.Fingerprint == fingerprint && link.LoginID == loginID && link.DeletedAt.IsZero() {
			// Return a copy to avoid race conditions
			linkCopy := link
			slog.Debug("Found login device link", "fingerprint", fingerprint, "loginID", loginID,
				"linkedAt", link.LinkedAt.Format(time.RFC3339),
				"expiresAt", link.ExpiresAt.Format(time.RFC3339))
			return linkCopy, nil
		}
	}

	slog.Debug("Login device link not found", "fingerprint", fingerprint, "loginID", loginID)
	return LoginDevice{}, fmt.Errorf("login device not found for fingerprint %s and login ID %s", fingerprint, loginID)
}

// UpdateLoginDeviceDisplayName updates the display name of a login-device link
func (r *InMemDeviceRepository) UpdateLoginDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	// Check if link exists
	loginDevice, exists := r.loginDevices[key]
	if !exists || !loginDevice.DeletedAt.IsZero() {
		slog.Debug("Login device link not found when updating display name", "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, errors.New("login device link not found")
	}

	// Update the display name
	loginDevice.DisplayName = displayName
	loginDevice.UpdatedAt = time.Now().UTC()
	r.loginDevices[key] = loginDevice

	// Return a copy to avoid race conditions
	result := loginDevice
	slog.Debug("Updated device display name", "fingerprint", fingerprint, "loginID", loginID, "displayName", displayName)
	return result, nil
}

// GetExpiryDuration returns the configured expiry duration for login-device links
func (r *InMemDeviceRepository) GetExpiryDuration() time.Duration {
	return r.options.ExpiryDuration
}

// WithTx returns the repository itself since in-memory implementation doesn't support transactions
func (r *InMemDeviceRepository) WithTx(tx interface{}) DeviceRepository {
	// In-memory implementation doesn't support transactions, so just return self
	return r
}
