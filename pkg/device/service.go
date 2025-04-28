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
func (s *DeviceService) RegisterDevice(ctx context.Context, fingerprint, userAgent string) (Device, error) {
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
		Fingerprint:    fingerprint,
		UserAgent:      userAgent,
		LastLogin:      now,
		CreatedAt:      now,
		LastModifiedAt: now,
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
	_, err := s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		return fmt.Errorf("device not found: %w", err)
	}

	// Link device to login with default expiry
	_, err = s.deviceRepository.LinkLoginToDevice(ctx, loginID, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to link device to login: %w", err)
	}

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
	devices, err := s.deviceRepository.FindDevicesByLogin(ctx, loginID)
	if err != nil {
		return nil, fmt.Errorf("failed to find devices for login: %w", err)
	}
	return devices, nil
}

// FindLoginsByDevice returns all logins linked to a specific device
func (s *DeviceService) FindLoginsByDevice(ctx context.Context, fingerprint string) ([]LoginInfo, error) {
	logins, err := s.deviceRepository.FindLoginsByDevice(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to find logins for device: %w", err)
	}
	res := []LoginInfo{}
	for _, login := range logins {
		loginInfo, err := s.loginRepository.GetLoginById(ctx, login.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get login info: %w", err)
		}
		login.Username = loginInfo.Username
		res = append(res, LoginInfo{
			ID:       login.ID,
			Username: login.Username,
		})
	}
	return res, nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (s *DeviceService) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (*LoginDevice, error) {
	loginDevice, err := s.deviceRepository.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	if err != nil {
		return nil, fmt.Errorf("failed to find login device: %w", err)
	}
	return loginDevice, nil
}

// ExtendLoginDeviceExpiry extends the expiration date of a login-device link
func (s *DeviceService) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string, days int) error {
	newExpiryDate := CalculateExpiryDate(days)
	err := s.deviceRepository.ExtendLoginDeviceExpiry(ctx, loginID, fingerprint, newExpiryDate)
	if err != nil {
		return fmt.Errorf("failed to extend login device expiry: %w", err)
	}
	return nil
}

func (s *DeviceService) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	return s.deviceRepository.GetDeviceByFingerprint(ctx, fingerprint)
}
