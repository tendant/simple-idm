package device

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DeviceService handles device recognition and management
type DeviceService struct {
	repository DeviceRepository
}

// NewDeviceService creates a new device service with the given repository
func NewDeviceService(repository DeviceRepository) *DeviceService {
	return &DeviceService{
		repository: repository,
	}
}

// RegisterDevice registers a new device or updates an existing one
func (s *DeviceService) RegisterDevice(ctx context.Context, fingerprint, userAgent string) (Device, error) {
	// Check if device already exists
	_, err := s.repository.GetDeviceByFingerprint(ctx, fingerprint)
	if err == nil {
		// Device exists, update last login time
		now := time.Now().UTC()
		updatedDevice, err := s.repository.UpdateDeviceLastLogin(ctx, fingerprint, now)
		if err != nil {
			return Device{}, fmt.Errorf("failed to update device last login: %w", err)
		}
		return updatedDevice, nil
	}

	// Create new device
	now := time.Now().UTC()
	newDevice := Device{
		Fingerprint:    fingerprint,
		UserAgent:      userAgent,
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
	}

	createdDevice, err := s.repository.CreateDevice(ctx, newDevice)
	if err != nil {
		return Device{}, fmt.Errorf("failed to create device: %w", err)
	}

	return createdDevice, nil
}

// LinkDeviceToLogin links a device to a login ID with expiration
func (s *DeviceService) LinkDeviceToLogin(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	// Ensure device exists
	_, err := s.repository.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		return fmt.Errorf("device not found: %w", err)
	}

	// Link device to login with default expiry
	_, err = s.repository.LinkLoginToDevice(ctx, loginID, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to link device to login: %w", err)
	}

	return nil
}

// IsDeviceLinkedToLogin checks if a device is linked to a login and not expired
func (s *DeviceService) IsDeviceLinkedToLogin(ctx context.Context, loginID uuid.UUID, fingerprint string) (bool, error) {
	// Get device link with expiry information
	_, isExpired, err := s.repository.GetLoginDeviceWithExpiry(ctx, loginID, fingerprint)
	if err != nil {
		return false, fmt.Errorf("error checking device link: %w", err)
	}

	// If link exists but is expired, it's not considered valid
	if isExpired {
		return false, nil
	}

	return true, nil
}

// ExtendLoginDeviceExpiry extends the expiration date of a login-device link
func (s *DeviceService) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string, days int) error {
	newExpiryDate := CalculateExpiryDate(days)
	err := s.repository.ExtendLoginDeviceExpiry(ctx, loginID, fingerprint, newExpiryDate)
	if err != nil {
		return fmt.Errorf("failed to extend login device expiry: %w", err)
	}
	return nil
}
