package device

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InMemDeviceRepository implements DeviceRepository using in-memory storage
type InMemDeviceRepository struct {
	devices      map[string]Device      // Fingerprint -> Device
	loginDevices map[string]LoginDevice // LoginID:Fingerprint -> LoginDevice
	mu           sync.RWMutex
}

// NewInMemDeviceRepository creates a new in-memory device repository
func NewInMemDeviceRepository() *InMemDeviceRepository {
	return &InMemDeviceRepository{
		devices:      make(map[string]Device),
		loginDevices: make(map[string]LoginDevice),
	}
}

// CreateDevice creates a new device in memory
func (r *InMemDeviceRepository) CreateDevice(ctx context.Context, device Device) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.devices[device.Fingerprint]; exists {
		return Device{}, errors.New("device already exists")
	}

	r.devices[device.Fingerprint] = device
	return device, nil
}

// GetDeviceByFingerprint retrieves a device by its fingerprint
func (r *InMemDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		return Device{}, errors.New("device not found")
	}

	return device, nil
}

// FindDevices returns all devices
func (r *InMemDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	devices := make([]Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	return devices, nil
}

// FindDevicesByLogin returns all devices linked to a specific login
func (r *InMemDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var devices []Device
	// Map to track fingerprints we've already added to avoid duplicates
	fingerprintMap := make(map[string]bool)

	for _, link := range r.loginDevices {
		if link.LoginID == loginID && link.DeletedAt.IsZero() {
			// Only process each fingerprint once
			if _, exists := fingerprintMap[link.Fingerprint]; !exists {
				fingerprintMap[link.Fingerprint] = true

				// Find the device with this fingerprint
				for _, device := range r.devices {
					if device.Fingerprint == link.Fingerprint {
						devices = append(devices, device)
						break
					}
				}
			}
		}
	}

	return devices, nil
}

// FindLoginsByDevice returns all logins linked to a specific device
func (r *InMemDeviceRepository) FindLoginsByDevice(ctx context.Context, fingerprint string) ([]LoginInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

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

	return loginInfos, nil
}

// UpdateDeviceLastLogin updates the last login time of a device
func (r *InMemDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLogin time.Time) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		return Device{}, errors.New("device not found")
	}

	device.LastLogin = lastLogin
	device.LastModifiedAt = time.Now().UTC()
	r.devices[fingerprint] = device

	return device, nil
}

// LinkLoginToDevice links a login to a device
func (r *InMemDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if device exists
	if _, exists := r.devices[fingerprint]; !exists {
		return LoginDevice{}, errors.New("device not found")
	}

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	// Check if link already exists
	if existingLink, exists := r.loginDevices[key]; exists {
		// Update the expiry date
		existingLink.ExpiresAt = CalculateExpiryDate(DefaultDeviceExpiryDays)
		r.loginDevices[key] = existingLink
		return existingLink, nil
	}

	// Create new link
	now := time.Now().UTC()
	loginDevice := LoginDevice{
		ID:          uuid.New(),
		LoginID:     loginID,
		Fingerprint: fingerprint,
		LinkedAt:    now,
		ExpiresAt:   CalculateExpiryDate(DefaultDeviceExpiryDays),
	}

	r.loginDevices[key] = loginDevice
	return loginDevice, nil
}

// GetLoginDeviceWithExpiry retrieves a login device link and checks if it's expired
func (r *InMemDeviceRepository) GetLoginDeviceWithExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	loginDevice, exists := r.loginDevices[key]
	if !exists {
		return LoginDevice{}, false, errors.New("login device link not found")
	}

	// Check if the link is expired
	now := time.Now().UTC()
	isExpired := loginDevice.ExpiresAt.Before(now)

	return loginDevice, isExpired, nil
}

// ExtendLoginDeviceExpiry extends the expiration date of a login device link
func (r *InMemDeviceRepository) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string, newExpiryDate time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	loginDevice, exists := r.loginDevices[key]
	if !exists {
		return errors.New("login device link not found")
	}

	loginDevice.ExpiresAt = newExpiryDate
	r.loginDevices[key] = loginDevice

	return nil
}

// UnlinkLoginToDevice removes the link between a login and a device
func (r *InMemDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a key for the login device map
	key := loginID.String() + ":" + fingerprint

	// Check if link exists
	if _, exists := r.loginDevices[key]; !exists {
		return errors.New("login device link not found")
	}

	// Remove the link
	loginDevice := r.loginDevices[key]
	loginDevice.DeletedAt = time.Now().UTC()
	r.loginDevices[key] = loginDevice
	return nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (r *InMemDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (*LoginDevice, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, link := range r.loginDevices {
		if link.Fingerprint == fingerprint && link.LoginID == loginID {
			// Return a copy to avoid race conditions
			linkCopy := link
			return &linkCopy, nil
		}
	}

	return nil, fmt.Errorf("login device not found for fingerprint %s and login ID %s", fingerprint, loginID)
}

// WithTx returns the repository itself since in-memory implementation doesn't support transactions
func (r *InMemDeviceRepository) WithTx(tx interface{}) DeviceRepository {
	// In-memory implementation doesn't support transactions, so just return self
	return r
}
