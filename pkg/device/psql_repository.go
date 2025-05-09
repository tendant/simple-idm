package device

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresDeviceRepository implements DeviceRepository using PostgreSQL
type PostgresDeviceRepository struct {
	db      DBTX
	options DeviceRepositoryOptions
}

// DBTX is an interface that allows us to use either a database connection or a transaction
type DBTX interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
}

// NewPostgresDeviceRepository creates a new PostgreSQL device repository
func NewPostgresDeviceRepository(db DBTX) *PostgresDeviceRepository {
	return &PostgresDeviceRepository{
		db:      db,
		options: DefaultDeviceRepositoryOptions(),
	}
}

// NewPostgresDeviceRepositoryWithOptions creates a new PostgreSQL device repository with custom options
func NewPostgresDeviceRepositoryWithOptions(db DBTX, options DeviceRepositoryOptions) *PostgresDeviceRepository {
	return &PostgresDeviceRepository{
		db:      db,
		options: options,
	}
}

// GetExpiryDuration returns the configured expiry duration for login-device links
func (r *PostgresDeviceRepository) GetExpiryDuration() time.Duration {
	return r.options.ExpiryDuration
}

// CreateDevice creates a new device in the database
func (r *PostgresDeviceRepository) CreateDevice(ctx context.Context, device Device) (Device, error) {
	// Check if device already exists
	_, err := r.GetDeviceByFingerprint(ctx, device.Fingerprint)
	if err == nil {
		slog.Debug("Device already exists", "fingerprint", device.Fingerprint)
		return Device{}, errors.New("device already exists")
	}

	// Set created_at if not already set
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}

	// Set last_login_at if not already set
	if device.LastLoginAt.IsZero() {
		device.LastLoginAt = time.Now().UTC()
	}

	// Set default device name and type if not provided
	if device.DeviceName == "" {
		device.DeviceName = determineDeviceName(device.UserAgent)
	}
	if device.DeviceType == "" {
		device.DeviceType = determineDeviceType(device.UserAgent)
	}

	// Check if we need to include device_id in the query
	var query string
	var args []interface{}

	if device.DeviceID != "" {
		// Include device_id in the query
		query = `
			INSERT INTO device (
				fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
			) RETURNING fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
		`
		args = []interface{}{
			device.Fingerprint,
			device.UserAgent,
			device.AcceptHeaders,
			device.Timezone,
			device.ScreenResolution,
			device.DeviceName,
			device.DeviceType,
			device.LastLoginAt,
			device.CreatedAt,
			device.DeviceID,
		}
		slog.Info("Creating mobile device with device ID", "fingerprint", device.Fingerprint, "deviceID", device.DeviceID)
	} else {
		// Standard query without device_id
		query = `
			INSERT INTO device (
				fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9
			) RETURNING fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
		`
		args = []interface{}{
			device.Fingerprint,
			device.UserAgent,
			device.AcceptHeaders,
			device.Timezone,
			device.ScreenResolution,
			device.DeviceName,
			device.DeviceType,
			device.LastLoginAt,
			device.CreatedAt,
		}
	}

	row := r.db.QueryRow(ctx, query, args...)

	var result Device
	var deviceID sql.NullString
	err = row.Scan(
		&result.Fingerprint,
		&result.UserAgent,
		&result.AcceptHeaders,
		&result.Timezone,
		&result.ScreenResolution,
		&result.DeviceName,
		&result.DeviceType,
		&result.LastLoginAt,
		&result.CreatedAt,
		&deviceID,
	)
	if err != nil {
		slog.Error("Failed to create device", "err", err, "fingerprint", device.Fingerprint)
		return Device{}, fmt.Errorf("failed to create device: %w", err)
	}

	// Set device ID if valid
	if deviceID.Valid {
		result.DeviceID = deviceID.String
	}

	slog.Debug("Device created", "fingerprint", result.Fingerprint)
	return result, nil
}

// GetDeviceByFingerprint retrieves a device by its fingerprint
func (r *PostgresDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	query := `
		SELECT fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
		FROM device
		WHERE fingerprint = $1
	`

	row := r.db.QueryRow(ctx, query, fingerprint)

	var device Device
	var deviceID sql.NullString
	err := row.Scan(
		&device.Fingerprint,
		&device.UserAgent,
		&device.AcceptHeaders,
		&device.Timezone,
		&device.ScreenResolution,
		&device.DeviceName,
		&device.DeviceType,
		&device.LastLoginAt,
		&device.CreatedAt,
		&deviceID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Device not found", "fingerprint", fingerprint)
			return Device{}, errors.New("device not found")
		}
		slog.Error("Failed to get device", "err", err, "fingerprint", fingerprint)
		return Device{}, fmt.Errorf("failed to get device: %w", err)
	}

	// Set device ID if valid
	if deviceID.Valid {
		device.DeviceID = deviceID.String
	}

	return device, nil
}

// FindDevices returns all devices
func (r *PostgresDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	query := `
		SELECT fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
		FROM device
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		slog.Error("Failed to find devices", "err", err)
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var deviceID sql.NullString
		err := rows.Scan(
			&device.Fingerprint,
			&device.UserAgent,
			&device.AcceptHeaders,
			&device.Timezone,
			&device.ScreenResolution,
			&device.DeviceName,
			&device.DeviceType,
			&device.LastLoginAt,
			&device.CreatedAt,
			&deviceID,
		)
		if err != nil {
			slog.Error("Failed to scan device", "err", err)
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		// Set device ID if valid
		if deviceID.Valid {
			device.DeviceID = deviceID.String
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		slog.Error("Error iterating over devices", "err", err)
		return nil, fmt.Errorf("error iterating over devices: %w", err)
	}

	slog.Debug("Found devices", "count", len(devices))
	return devices, nil
}

// FindDevicesByLogin returns all devices linked to a specific login
func (r *PostgresDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	query := `
		SELECT d.fingerprint, d.user_agent, d.accept_headers, d.timezone, d.screen_resolution, d.device_name, d.device_type, d.last_login_at, d.created_at, d.device_id
		FROM device d
		JOIN login_device ld ON d.fingerprint = ld.fingerprint
		WHERE ld.login_id = $1 AND ld.deleted_at IS NULL
		ORDER BY d.last_login_at DESC
	`

	rows, err := r.db.Query(ctx, query, loginID)
	if err != nil {
		slog.Error("Failed to find devices by login", "err", err, "loginID", loginID)
		return nil, fmt.Errorf("failed to find devices by login: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var deviceID sql.NullString
		err := rows.Scan(
			&device.Fingerprint,
			&device.UserAgent,
			&device.AcceptHeaders,
			&device.Timezone,
			&device.ScreenResolution,
			&device.DeviceName,
			&device.DeviceType,
			&device.LastLoginAt,
			&device.CreatedAt,
			&deviceID,
		)
		if err != nil {
			slog.Error("Failed to scan device", "err", err)
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		// Set device ID if valid
		if deviceID.Valid {
			device.DeviceID = deviceID.String
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		slog.Error("Error iterating over devices", "err", err)
		return nil, fmt.Errorf("error iterating over devices: %w", err)
	}

	slog.Debug("Found devices by login", "loginID", loginID, "count", len(devices))
	return devices, nil
}

// UpdateDeviceLastLogin updates the last login time of a device
func (r *PostgresDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLogin time.Time) (Device, error) {
	query := `
		UPDATE device
		SET last_login_at = $2
		WHERE fingerprint = $1
		RETURNING fingerprint, user_agent, accept_headers, timezone, screen_resolution, device_name, device_type, last_login_at, created_at, device_id
	`

	row := r.db.QueryRow(ctx, query, fingerprint, lastLogin)

	var device Device
	var deviceID sql.NullString
	err := row.Scan(
		&device.Fingerprint,
		&device.UserAgent,
		&device.AcceptHeaders,
		&device.Timezone,
		&device.ScreenResolution,
		&device.DeviceName,
		&device.DeviceType,
		&device.LastLoginAt,
		&device.CreatedAt,
		&deviceID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Device not found for update", "fingerprint", fingerprint)
			return Device{}, errors.New("device not found")
		}
		slog.Error("Failed to update device last login", "err", err, "fingerprint", fingerprint)
		return Device{}, fmt.Errorf("failed to update device last login: %w", err)
	}

	// Set device ID if valid
	if deviceID.Valid {
		device.DeviceID = deviceID.String
	}

	return device, nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (r *PostgresDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (LoginDevice, error) {
	query := `
		SELECT id, login_id, fingerprint, display_name, linked_at, expires_at, deleted_at, created_at, updated_at
		FROM login_device
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
		LIMIT 1
	`

	row := r.db.QueryRow(ctx, query, fingerprint, loginID)

	var loginDevice LoginDevice
	var deletedAt sql.NullTime
	err := row.Scan(
		&loginDevice.ID,
		&loginDevice.LoginID,
		&loginDevice.Fingerprint,
		&loginDevice.DisplayName,
		&loginDevice.LinkedAt,
		&loginDevice.ExpiresAt,
		&deletedAt,
		&loginDevice.CreatedAt,
		&loginDevice.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Login device link not found", "fingerprint", fingerprint, "loginID", loginID)
			return LoginDevice{}, fmt.Errorf("login device not found for fingerprint %s and login ID %s", fingerprint, loginID)
		}
		slog.Error("Failed to find login device", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, fmt.Errorf("failed to find login device: %w", err)
	}

	// Set DeletedAt if valid
	if deletedAt.Valid {
		loginDevice.DeletedAt = deletedAt.Time
	}

	slog.Debug("Found login device link", "fingerprint", fingerprint, "loginID", loginID,
		"linkedAt", loginDevice.LinkedAt.Format(time.RFC3339),
		"expiresAt", loginDevice.ExpiresAt.Format(time.RFC3339))
	return loginDevice, nil
}

// LinkLoginToDevice links a login to a device
func (r *PostgresDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	// Check if the device exists
	device, err := r.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		slog.Error("Device not found for linking", "err", err, "fingerprint", fingerprint)
		return LoginDevice{}, fmt.Errorf("device not found: %w", err)
	}

	// Check if the login-device link already exists
	existingLoginDevice, err := r.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	if err == nil && existingLoginDevice.DeletedAt.IsZero() {
		// Link already exists and is not deleted
		slog.Debug("Login device link already exists", "fingerprint", fingerprint, "loginID", loginID)
		return existingLoginDevice, nil
	}

	// Create the link
	now := time.Now().UTC()
	expiresAt := CalculateExpiryDate(r.options.ExpiryDuration)

	query := `
		INSERT INTO login_device (login_id, fingerprint, display_name, linked_at, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, login_id, fingerprint, display_name, linked_at, expires_at, deleted_at, updated_at, created_at
	`

	row := r.db.QueryRow(ctx, query, loginID, fingerprint, device.DeviceName, now, expiresAt, now, now)

	var loginDevice LoginDevice
	var deletedAt sql.NullTime
	err = row.Scan(
		&loginDevice.ID,
		&loginDevice.LoginID,
		&loginDevice.Fingerprint,
		&loginDevice.DisplayName,
		&loginDevice.LinkedAt,
		&loginDevice.ExpiresAt,
		&deletedAt,
		&loginDevice.UpdatedAt,
		&loginDevice.CreatedAt,
	)
	if err != nil {
		slog.Error("Failed to create device link", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, fmt.Errorf("failed to create device link: %w", err)
	}

	// Set DeletedAt if valid
	if deletedAt.Valid {
		loginDevice.DeletedAt = deletedAt.Time
	}

	slog.Debug("Created new device link", "fingerprint", fingerprint, "loginID", loginID,
		"expiry", loginDevice.ExpiresAt.Format(time.RFC3339))
	return loginDevice, nil
}

// UnlinkLoginToDevice removes the link between a login and a device
func (r *PostgresDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	query := `
		UPDATE login_device
		SET deleted_at = $3
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.Exec(ctx, query, fingerprint, loginID, time.Now().UTC())
	if err != nil {
		slog.Error("Failed to unlink device", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return fmt.Errorf("failed to unlink device: %w", err)
	}

	if result.RowsAffected() == 0 {
		slog.Debug("Login device link not found when unlinking", "fingerprint", fingerprint, "loginID", loginID)
		return errors.New("login device link not found")
	}

	slog.Debug("Device link marked as deleted", "fingerprint", fingerprint, "loginID", loginID)
	return nil
}

// UpdateLoginDeviceDisplayName updates the display name of a login-device link
func (r *PostgresDeviceRepository) UpdateLoginDeviceDisplayName(ctx context.Context, loginID uuid.UUID, fingerprint string, displayName string) (LoginDevice, error) {
	// Update the display name in the database
	query := `
		UPDATE login_device
		SET display_name = $3, updated_at = $4
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
		RETURNING id, login_id, fingerprint, display_name, linked_at, expires_at, deleted_at, updated_at, created_at
	`

	row := r.db.QueryRow(ctx, query, fingerprint, loginID, displayName, time.Now().UTC())

	var updatedLoginDevice LoginDevice
	var deletedAt sql.NullTime
	err := row.Scan(
		&updatedLoginDevice.ID,
		&updatedLoginDevice.LoginID,
		&updatedLoginDevice.Fingerprint,
		&updatedLoginDevice.DisplayName,
		&updatedLoginDevice.LinkedAt,
		&updatedLoginDevice.ExpiresAt,
		&deletedAt,
		&updatedLoginDevice.UpdatedAt,
		&updatedLoginDevice.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Login device link not found when updating display name", "fingerprint", fingerprint, "loginID", loginID)
			return LoginDevice{}, errors.New("login device link not found")
		}
		slog.Error("Failed to update device display name", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, fmt.Errorf("failed to update device display name: %w", err)
	}

	// Set DeletedAt if valid
	if deletedAt.Valid {
		updatedLoginDevice.DeletedAt = deletedAt.Time
	}

	slog.Debug("Updated device display name", "fingerprint", fingerprint, "loginID", loginID, "displayName", displayName)
	return updatedLoginDevice, nil
}

func (r *PostgresDeviceRepository) ExtendLoginDeviceExpiry(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	query := `
		UPDATE login_device
		SET linked_at = $3, updated_at = $4, expires_at = $5
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
	`
	_, err := r.db.Exec(ctx, query, fingerprint, loginID, time.Now().UTC(), time.Now().UTC(), CalculateExpiryDate(r.options.ExpiryDuration))
	if err != nil {
		slog.Error("Failed to extend device expiry", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return fmt.Errorf("failed to extend device expiry: %w", err)
	}
	return nil
}

// WithTx returns a new repository with the given transaction
func (r *PostgresDeviceRepository) WithTx(tx interface{}) DeviceRepository {
	// Check if the transaction is nil
	if tx == nil {
		return r
	}

	// Try to convert the interface to a pgx.Tx
	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		// If it's not a pgx.Tx, log a warning and return the original repository
		slog.Warn("Unsupported transaction type", "type", reflect.TypeOf(tx))
		return r
	}

	// Use the pgx.Tx with the repository
	return NewPostgresDeviceRepository(pgxTx)
}

// Helper functions for device name and type detection

// determineDeviceName extracts a human-readable device name from the user agent
func determineDeviceName(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	// Check for common mobile devices
	if contains(userAgent, "iPhone") {
		return "iPhone"
	} else if contains(userAgent, "iPad") {
		return "iPad"
	} else if contains(userAgent, "Android") && (contains(userAgent, "Mobile") || contains(userAgent, "Pixel") || contains(userAgent, "Samsung") || contains(userAgent, "SM-")) {
		if contains(userAgent, "Pixel") {
			return "Google Pixel"
		} else if contains(userAgent, "Samsung") || contains(userAgent, "SM-") {
			return "Samsung Phone"
		}
		return "Android Phone"
	} else if contains(userAgent, "Android") {
		return "Android Tablet"
	}

	// Check for desktop operating systems
	if contains(userAgent, "Macintosh") || contains(userAgent, "Mac OS X") {
		return "Mac"
	} else if contains(userAgent, "Windows") {
		return "Windows PC"
	} else if contains(userAgent, "Linux") {
		return "Linux"
	} else if contains(userAgent, "CrOS") {
		return "Chromebook"
	}

	// Default to a generic name based on browser
	if contains(userAgent, "Chrome") {
		return "Chrome Browser"
	} else if contains(userAgent, "Firefox") {
		return "Firefox Browser"
	} else if contains(userAgent, "Safari") {
		return "Safari Browser"
	} else if contains(userAgent, "Edge") {
		return "Edge Browser"
	}

	return "Unknown Device"
}

// determineDeviceType categorizes the device as Mobile, Tablet, Desktop, or Other
func determineDeviceType(userAgent string) string {
	if userAgent == "" {
		return DeviceTypeOther
	}

	// Mobile devices
	if contains(userAgent, "iPhone") ||
		(contains(userAgent, "Android") && contains(userAgent, "Mobile")) ||
		contains(userAgent, "Windows Phone") {
		return DeviceTypeMobile
	}

	// Tablets
	if contains(userAgent, "iPad") ||
		(contains(userAgent, "Android") && !contains(userAgent, "Mobile")) {
		return DeviceTypeTablet
	}

	// Desktops
	if contains(userAgent, "Windows") ||
		contains(userAgent, "Macintosh") ||
		contains(userAgent, "Linux") ||
		contains(userAgent, "CrOS") {
		return DeviceTypeDesktop
	}

	return DeviceTypeOther
}

// contains is a helper function to check if a string contains a substring (case insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
