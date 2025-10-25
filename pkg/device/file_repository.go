package device

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileDeviceRepository implements DeviceRepository using file-based storage
type FileDeviceRepository struct {
	dataDir       string
	devices       map[string]*Device       // Key: fingerprint
	loginDevices  map[string]*LoginDevice  // Key: "loginID:fingerprint"
	expiryDuration time.Duration
	mutex         sync.RWMutex
}

// deviceData represents the structure of data stored in the JSON file
type deviceData struct {
	Devices      []*Device      `json:"devices"`
	LoginDevices []*LoginDevice `json:"login_devices"`
}

// NewFileDeviceRepository creates a new file-based device repository
func NewFileDeviceRepository(dataDir string, options DeviceRepositoryOptions) (*FileDeviceRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	expiryDuration := options.ExpiryDuration
	if expiryDuration == 0 {
		expiryDuration = DefaultDeviceExpiryDuration
	}

	repo := &FileDeviceRepository{
		dataDir:       dataDir,
		devices:       make(map[string]*Device),
		loginDevices:  make(map[string]*LoginDevice),
		expiryDuration: expiryDuration,
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// CreateDevice creates a new device
func (r *FileDeviceRepository) CreateDevice(ctx context.Context, device Device) (Device, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.devices[device.Fingerprint]; exists {
		return Device{}, fmt.Errorf("device already exists: %s", device.Fingerprint)
	}

	device.CreatedAt = time.Now().UTC()
	device.LastLoginAt = device.CreatedAt

	deviceCopy := device
	r.devices[device.Fingerprint] = &deviceCopy

	if err := r.save(); err != nil {
		delete(r.devices, device.Fingerprint)
		return Device{}, fmt.Errorf("failed to save: %w", err)
	}

	return device, nil
}

// GetDeviceByFingerprint retrieves a device by fingerprint
func (r *FileDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		return Device{}, fmt.Errorf("device not found: %s", fingerprint)
	}

	return *device, nil
}

// FindDevices retrieves all devices
func (r *FileDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	devices := make([]Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, *device)
	}

	return devices, nil
}

// FindDevicesByLogin retrieves all devices linked to a login
func (r *FileDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var devices []Device
	for _, loginDevice := range r.loginDevices {
		if loginDevice.LoginID == loginID && !loginDevice.IsExpired() {
			if device, exists := r.devices[loginDevice.Fingerprint]; exists {
				devices = append(devices, *device)
			}
		}
	}

	return devices, nil
}

// UpdateDeviceLastLogin updates the last login time for a device
func (r *FileDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLogin time.Time) (Device, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[fingerprint]
	if !exists {
		return Device{}, fmt.Errorf("device not found: %s", fingerprint)
	}

	device.LastLoginAt = lastLogin

	if err := r.save(); err != nil {
		return Device{}, fmt.Errorf("failed to save: %w", err)
	}

	return *device, nil
}

// FindLoginDeviceByFingerprintAndLoginID finds a login-device link
func (r *FileDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	key := r.makeKey(loginID, fingerprint)
	loginDevice, exists := r.loginDevices[key]
	if !exists {
		return LoginDevice{}, fmt.Errorf("device not found")
	}

	return *loginDevice, nil
}

// LinkLoginToDevice creates a link between a login and a device
func (r *FileDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := r.makeKey(loginID, fingerprint)

	// Check if link already exists
	if existing, exists := r.loginDevices[key]; exists {
		// Update expiry
		existing.ExpiresAt = CalculateExpiryDate(r.expiryDuration)
		existing.UpdatedAt = time.Now().UTC()

		if err := r.save(); err != nil {
			return LoginDevice{}, fmt.Errorf("failed to save: %w", err)
		}

		return *existing, nil
	}

	// Create new link
	now := time.Now().UTC()
	loginDevice := &LoginDevice{
		ID:          uuid.New(),
		LoginID:     loginID,
		Fingerprint: fingerprint,
		DisplayName: "",
		LinkedAt:    now,
		ExpiresAt:   CalculateExpiryDate(r.expiryDuration),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	r.loginDevices[key] = loginDevice

	if err := r.save(); err != nil {
		delete(r.loginDevices, key)
		return LoginDevice{}, fmt.Errorf("failed to save: %w", err)
	}

	return *loginDevice, nil
}

// ExtendLoginDeviceExpiry extends the expiry date of a login-device link
func (r *FileDeviceRepository) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := r.makeKey(loginID, fingerprint)
	loginDevice, exists := r.loginDevices[key]
	if !exists {
		return fmt.Errorf("device link not found")
	}

	loginDevice.ExpiresAt = CalculateExpiryDate(r.expiryDuration)
	loginDevice.UpdatedAt = time.Now().UTC()

	return r.save()
}

// UnlinkLoginToDevice removes the link between a login and a device
func (r *FileDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := r.makeKey(loginID, fingerprint)
	if _, exists := r.loginDevices[key]; !exists {
		return fmt.Errorf("device link not found")
	}

	delete(r.loginDevices, key)
	return r.save()
}

// UpdateLoginDeviceDisplayName updates the display name of a login-device link
func (r *FileDeviceRepository) UpdateLoginDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := r.makeKey(loginID, fingerprint)
	loginDevice, exists := r.loginDevices[key]
	if !exists {
		return LoginDevice{}, fmt.Errorf("device link not found")
	}

	loginDevice.DisplayName = displayName
	loginDevice.UpdatedAt = time.Now().UTC()

	if err := r.save(); err != nil {
		return LoginDevice{}, fmt.Errorf("failed to save: %w", err)
	}

	return *loginDevice, nil
}

// GetExpiryDuration returns the configured expiry duration
func (r *FileDeviceRepository) GetExpiryDuration() time.Duration {
	return r.expiryDuration
}

// WithTx returns a new repository with the given transaction
// File-based implementation doesn't support transactions, returns self
func (r *FileDeviceRepository) WithTx(tx interface{}) DeviceRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// makeKey creates a composite key for login-device links
func (r *FileDeviceRepository) makeKey(loginID uuid.UUID, fingerprint string) string {
	return fmt.Sprintf("%s:%s", loginID.String(), fingerprint)
}

// load reads device data from file
func (r *FileDeviceRepository) load() error {
	filePath := filepath.Join(r.dataDir, "devices.json")

	// If file doesn't exist, start with empty maps
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty maps
	if len(data) == 0 {
		return nil
	}

	var devData deviceData
	if err := json.Unmarshal(data, &devData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to maps
	r.devices = make(map[string]*Device)
	for _, device := range devData.Devices {
		r.devices[device.Fingerprint] = device
	}

	r.loginDevices = make(map[string]*LoginDevice)
	for _, loginDevice := range devData.LoginDevices {
		key := r.makeKey(loginDevice.LoginID, loginDevice.Fingerprint)
		r.loginDevices[key] = loginDevice
	}

	return nil
}

// save writes device data to file atomically
func (r *FileDeviceRepository) save() error {
	// Convert maps to slices
	devices := make([]*Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	loginDevices := make([]*LoginDevice, 0, len(r.loginDevices))
	for _, loginDevice := range r.loginDevices {
		loginDevices = append(loginDevices, loginDevice)
	}

	data := deviceData{
		Devices:      devices,
		LoginDevices: loginDevices,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "devices.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "devices.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
