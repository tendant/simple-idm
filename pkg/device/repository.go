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
	LastLoginAt      time.Time
	CreatedAt        time.Time
}

type LoginDevice struct {
	ID          uuid.UUID
	LoginID     uuid.UUID
	Fingerprint string
	LinkedAt    time.Time
	ExpiresAt   time.Time
	DeletedAt   time.Time
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
	FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (*LoginDevice, error)

	// Link operations
	LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error)
	UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error

	// Transaction support
	WithTx(tx interface{}) DeviceRepository
}

const (
	DefaultDeviceExpiryDays = 90 // Default expiration is 90 days
)

// CalculateExpiryDate returns a time.Time that is days in the future from now
func CalculateExpiryDate(days int) time.Time {
	return time.Now().UTC().AddDate(0, 0, days)
}
