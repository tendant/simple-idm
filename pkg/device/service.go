package device

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
)

// DeviceService handles device recognition and management
type DeviceService struct {
	deviceRepository DeviceRepository
	loginRepository  login.LoginRepository
}

// NewDeviceService creates a new device service with the given repository
func NewDeviceService(deviceRepository DeviceRepository, loginRepository login.LoginRepository) *DeviceService {
	return &DeviceService{
		deviceRepository: deviceRepository,
		loginRepository:  loginRepository,
	}
}

// RegisterDevice registers a new device or updates an existing one
func (s *DeviceService) RegisterDevice(ctx context.Context, fingerprint string, fingerprintData FingerprintData) (Device, error) {
	// Check if device already exists
	_, err := s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
	if err == nil {
		// Device exists, update last login time
		slog.Info("device exsits, update last login")
		now := time.Now().UTC()
		updatedDevice, err := s.deviceRepository.UpdateDeviceLastLogin(ctx, fingerprint, now)
		if err != nil {
			return Device{}, fmt.Errorf("failed to update device last login: %w", err)
		}
		return updatedDevice, nil
	}

	slog.Info("device not exist, creating new device")
	// Create new device
	now := time.Now().UTC()
	newDevice := Device{
		Fingerprint: fingerprint,
		UserAgent:   fingerprintData.UserAgent,
		AcceptHeaders: fingerprintData.AcceptHeaders,
		Timezone: fingerprintData.Timezone,
		ScreenResolution: fingerprintData.ScreenResolution,
		LastLoginAt: now,
		CreatedAt:   now,
	}
	createdDevice, err := s.deviceRepository.CreateDevice(ctx, newDevice)
	if err != nil {
		return Device{}, fmt.Errorf("failed to create device: %w", err)
	}

	return createdDevice, nil
}

// LinkDeviceToLogin links a device to a login ID with expiration
func (s *DeviceService) LinkDeviceToLogin(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	// Ensure device exists
	device, err := s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		slog.Error("Failed to find device for linking", "fingerprint", fingerprint, "loginID", loginID, "error", err)
		return fmt.Errorf("device not found: %w", err)
	}

	slog.Info("Linking device to login",
		"fingerprint", fingerprint,
		"loginID", loginID,
		"userAgent", device.UserAgent,
		"timezone", device.Timezone,
		"screenResolution", device.ScreenResolution)

	// Link device to login with default expiry
	loginDevice, err := s.deviceRepository.LinkLoginToDevice(ctx, loginID, fingerprint)
	if err != nil {
		slog.Error("Failed to link device to login", "fingerprint", fingerprint, "loginID", loginID, "error", err)
		return fmt.Errorf("failed to link device to login: %w", err)
	}

	slog.Info("Device successfully linked to login",
		"fingerprint", fingerprint,
		"loginID", loginID,
		"expiresAt", loginDevice.ExpiresAt.Format(time.RFC3339))

	return nil
}

// FindAllDevices returns all devices in the system
func (s *DeviceService) FindAllDevices(ctx context.Context) ([]Device, error) {
	devices, err := s.deviceRepository.FindDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}
	return devices, nil
}

// FindDevicesByLogin returns all devices linked to a specific login
func (s *DeviceService) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	slog.Debug("Finding devices for login", "loginID", loginID)
	devices, err := s.deviceRepository.FindDevicesByLogin(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find devices for login", "loginID", loginID, "error", err)
		return nil, fmt.Errorf("failed to find devices for login: %w", err)
	}
	slog.Debug("Found devices for login", "loginID", loginID, "deviceCount", len(devices))
	return devices, nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (s *DeviceService) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (*LoginDevice, error) {
	loginDevice, err := s.deviceRepository.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	if err != nil {
		return nil, fmt.Errorf("failed to find login device: %w", err)
	}
	return loginDevice, nil
}

func (s *DeviceService) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	return s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
}

// UnlinkLoginFromDevice removes the link between a login and a device
func (s *DeviceService) UnlinkLoginFromDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	// Ensure device exists
	device, err := s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		slog.Error("Failed to find device for unlinking", "fingerprint", fingerprint, "loginID", loginID, "error", err)
		return fmt.Errorf("device not found: %w", err)
	}

	slog.Info("Unlinking device from login",
		"fingerprint", fingerprint,
		"loginID", loginID,
		"userAgent", device.UserAgent,
		"lastLogin", device.LastLoginAt.Format(time.RFC3339))

	// Unlink device from login
	err = s.deviceRepository.UnlinkLoginToDevice(ctx, loginID, fingerprint)
	if err != nil {
		slog.Error("Failed to unlink device from login", "fingerprint", fingerprint, "loginID", loginID, "error", err)
		return fmt.Errorf("failed to unlink device from login: %w", err)
	}

	slog.Info("Device successfully unlinked from login", "fingerprint", fingerprint, "loginID", loginID)
	return nil
}
