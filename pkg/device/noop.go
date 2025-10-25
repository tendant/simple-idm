package device

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NoOpDeviceRepository is a no-op implementation of DeviceRepository.
// This allows DeviceService to be created without database dependencies
// when device tracking is not needed.
type NoOpDeviceRepository struct{}

// NewNoOpDeviceRepository creates a new no-op device repository.
// Use this when you don't need device tracking/recognition functionality.
func NewNoOpDeviceRepository() DeviceRepository {
	return &NoOpDeviceRepository{}
}

func (r *NoOpDeviceRepository) CreateDevice(ctx context.Context, device Device) (Device, error) {
	return Device{}, fmt.Errorf("device tracking not configured")
}

func (r *NoOpDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	return Device{}, fmt.Errorf("device not found")
}

func (r *NoOpDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLoginAt time.Time) (Device, error) {
	return Device{}, fmt.Errorf("device tracking not configured")
}

func (r *NoOpDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	return []Device{}, nil
}

func (r *NoOpDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	return []Device{}, nil
}

func (r *NoOpDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error) {
	return LoginDevice{}, fmt.Errorf("device not found")
}

func (r *NoOpDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	return LoginDevice{}, nil // Silently succeed with empty result
}

func (r *NoOpDeviceRepository) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	return nil // Silently succeed
}

func (r *NoOpDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	return nil // Silently succeed
}

func (r *NoOpDeviceRepository) WithTx(tx interface{}) DeviceRepository {
	return r // Return self for chaining
}

func (r *NoOpDeviceRepository) UpdateLoginDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error) {
	return LoginDevice{}, fmt.Errorf("device tracking not configured")
}

func (r *NoOpDeviceRepository) GetExpiryDuration() time.Duration {
	return 0
}

// NoOpDeviceService is a no-op implementation of DeviceService.
// This allows services that depend on DeviceService to work without
// actual device tracking functionality when device recognition is not needed/configured.
//
// All methods return errors or empty results indicating device tracking is not configured.
type NoOpDeviceService struct{}

// NewNoOpDeviceService creates a new no-op device service.
// Use this when you don't need device tracking/recognition functionality.
func NewNoOpDeviceService() *NoOpDeviceService {
	return &NoOpDeviceService{}
}

func (n *NoOpDeviceService) GetDeviceExpiration() time.Duration {
	return 0
}

func (n *NoOpDeviceService) RegisterDevice(ctx context.Context, fingerprint string, fingerprintData FingerprintData) (Device, error) {
	return Device{}, fmt.Errorf("device tracking not configured")
}

func (n *NoOpDeviceService) UpdateDeviceLastLogin(ctx context.Context, fingerprint string) (Device, error) {
	return Device{}, fmt.Errorf("device tracking not configured")
}

func (n *NoOpDeviceService) LinkDeviceToLogin(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	// Silently succeed - device linking not available but shouldn't block login
	return nil
}

func (n *NoOpDeviceService) FindAllDevices(ctx context.Context) ([]Device, error) {
	return []Device{}, nil // Return empty slice
}

func (n *NoOpDeviceService) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	return []Device{}, nil // Return empty slice
}

func (n *NoOpDeviceService) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error) {
	// Return empty result - device not found (which is expected when device tracking is disabled)
	return LoginDevice{}, fmt.Errorf("device not found")
}

func (n *NoOpDeviceService) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	return Device{}, fmt.Errorf("device tracking not configured")
}

func (n *NoOpDeviceService) UnlinkLoginFromDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	// Silently succeed - nothing to unlink
	return nil
}

func (n *NoOpDeviceService) UpdateDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error) {
	return LoginDevice{}, fmt.Errorf("device tracking not configured")
}

func (n *NoOpDeviceService) RememberDevice(ctx context.Context, fingerprint FingerprintData, loginID uuid.UUID) (bool, error) {
	// Return false - device not remembered (but don't error, as this shouldn't block login)
	return false, nil
}
