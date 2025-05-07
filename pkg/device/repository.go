package device

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Device struct {
	Fingerprint      string
	UserAgent        string
	AcceptHeaders    string
	Timezone         string
	ScreenResolution string
	DeviceName       string
	DeviceType       string
	LastLoginAt      time.Time
	CreatedAt        time.Time
	DeviceID         uuid.UUID
}

type LoginDevice struct {
	ID          uuid.UUID
	LoginID     uuid.UUID
	Fingerprint string
	DisplayName string
	LinkedAt    time.Time
	ExpiresAt   time.Time
	DeletedAt   time.Time
	UpdatedAt   time.Time
	CreatedAt   time.Time
}

// IsExpired checks if the login device link has expired
func (ld *LoginDevice) IsExpired() bool {
	return time.Now().UTC().After(ld.ExpiresAt)
}

type LoginInfo struct {
	ID       uuid.UUID
	Username string
}

// DeviceRepository defines the interface for device storage operations
type DeviceRepository interface {
	// CRUD operations (delete is not supported for now)
	CreateDevice(ctx context.Context, device Device) (Device, error)
	GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error)
	FindDevices(ctx context.Context) ([]Device, error)
	FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error)
	UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLogin time.Time) (Device, error)
	FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error)

	// Link operations
	LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error)
	ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) error
	UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error

	// Transaction support
	WithTx(tx interface{}) DeviceRepository

	// UpdateLoginDeviceDisplayName updates the display name of a login-device link
	UpdateLoginDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error)

	// GetExpiryDuration returns the configured expiry duration for login-device links
	GetExpiryDuration() time.Duration
}

const (
	DefaultDeviceExpiryDuration = 90 * 24 * time.Hour // Default expiration is 90 days

	// Device types
	DeviceTypeMobile  = "mobile"
	DeviceTypeTablet  = "tablet"
	DeviceTypeDesktop = "desktop"
	DeviceTypeOther   = "other"
)

// DeviceRepositoryOptions contains options for configuring the device repository
type DeviceRepositoryOptions struct {
	ExpiryDuration time.Duration // Duration for device expiration
}

// DefaultDeviceRepositoryOptions returns the default options for the device repository
func DefaultDeviceRepositoryOptions() DeviceRepositoryOptions {
	return DeviceRepositoryOptions{
		ExpiryDuration: DefaultDeviceExpiryDuration,
	}
}

// CalculateExpiryDate returns a time.Time that is the duration in the future from now
func CalculateExpiryDate(expiryDuration time.Duration) time.Time {
	return time.Now().UTC().Add(expiryDuration)
}
