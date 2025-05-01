package device

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// SQL queries as constants
const (
	createDeviceSQL = `
		INSERT INTO device (
			fingerprint, user_agent, accept_headers, timezone, screen_resolution, last_login_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		) RETURNING fingerprint, user_agent, accept_headers, timezone, screen_resolution, last_login_at, created_at
	`

	getDeviceByFingerprintSQL = `
		SELECT fingerprint, user_agent, accept_headers, timezone, screen_resolution, last_login_at, created_at
		FROM device
		WHERE fingerprint = $1
	`

	findDevicesSQL = `
		SELECT fingerprint, user_agent, accept_headers, timezone, screen_resolution, last_login_at, created_at
		FROM device
		ORDER BY created_at DESC
	`

	findDevicesByLoginSQL = `
		SELECT d.fingerprint, d.user_agent, d.accept_headers, d.timezone, d.screen_resolution, d.last_login_at, d.created_at
		FROM device d
		JOIN login_device ld ON d.fingerprint = ld.fingerprint
		WHERE ld.login_id = $1 AND ld.deleted_at IS NULL
		GROUP BY d.fingerprint
		ORDER BY d.last_login_at DESC
	`

	updateDeviceLastLoginSQL = `
		UPDATE device
		SET last_login_at = $2
		WHERE fingerprint = $1
		RETURNING fingerprint, user_agent, accept_headers, timezone, screen_resolution, last_login_at, created_at
	`

	findLoginDeviceByFingerprintAndLoginIDSQL = `
		SELECT id, login_id, fingerprint, linked_at, expires_at, deleted_at
		FROM login_device
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
	`

	updateLoginDeviceExpirySQL = `
		UPDATE login_device
		SET expires_at = $3
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
		RETURNING id, login_id, fingerprint, linked_at, expires_at, deleted_at
	`

	createLoginDeviceSQL = `
		INSERT INTO login_device (
			login_id, fingerprint, linked_at, expires_at
		) VALUES (
			$1, $2, $3, $4
		) RETURNING id, login_id, fingerprint, linked_at, expires_at, deleted_at
	`

	unlinkLoginDeviceSQL = `
		UPDATE login_device
		SET deleted_at = $3
		WHERE fingerprint = $1 AND login_id = $2 AND deleted_at IS NULL
	`
)

// PostgresDeviceRepository implements DeviceRepository using PostgreSQL
type PostgresDeviceRepository struct {
	db DBTX
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
		db: db,
	}
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

	row := r.db.QueryRow(ctx, createDeviceSQL,
		device.Fingerprint,
		device.UserAgent,
		device.AcceptHeaders,
		device.Timezone,
		device.ScreenResolution,
		device.LastLoginAt,
		device.CreatedAt,
	)

	var result Device
	err = row.Scan(
		&result.Fingerprint,
		&result.UserAgent,
		&result.AcceptHeaders,
		&result.Timezone,
		&result.ScreenResolution,
		&result.LastLoginAt,
		&result.CreatedAt,
	)
	if err != nil {
		slog.Error("Failed to create device", "err", err, "fingerprint", device.Fingerprint)
		return Device{}, fmt.Errorf("failed to create device: %w", err)
	}

	slog.Debug("Device created", "fingerprint", result.Fingerprint)
	return result, nil
}

// GetDeviceByFingerprint retrieves a device by its fingerprint
func (r *PostgresDeviceRepository) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (Device, error) {
	row := r.db.QueryRow(ctx, getDeviceByFingerprintSQL, fingerprint)

	var device Device
	err := row.Scan(
		&device.Fingerprint,
		&device.UserAgent,
		&device.AcceptHeaders,
		&device.Timezone,
		&device.ScreenResolution,
		&device.LastLoginAt,
		&device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Device not found", "fingerprint", fingerprint)
			return Device{}, errors.New("device not found")
		}
		slog.Error("Failed to get device", "err", err, "fingerprint", fingerprint)
		return Device{}, fmt.Errorf("failed to get device: %w", err)
	}

	slog.Debug("Device found", "fingerprint", fingerprint)
	return device, nil
}

// FindDevices returns all devices
func (r *PostgresDeviceRepository) FindDevices(ctx context.Context) ([]Device, error) {
	rows, err := r.db.Query(ctx, findDevicesSQL)
	if err != nil {
		slog.Error("Failed to find devices", "err", err)
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(
			&device.Fingerprint,
			&device.UserAgent,
			&device.AcceptHeaders,
			&device.Timezone,
			&device.ScreenResolution,
			&device.LastLoginAt,
			&device.CreatedAt,
		)
		if err != nil {
			slog.Error("Failed to scan device", "err", err)
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		slog.Error("Error iterating device rows", "err", err)
		return nil, fmt.Errorf("error iterating device rows: %w", err)
	}

	slog.Debug("Found all devices", "deviceCount", len(devices))
	return devices, nil
}

// FindDevicesByLogin returns all devices linked to a specific login
func (r *PostgresDeviceRepository) FindDevicesByLogin(ctx context.Context, loginID uuid.UUID) ([]Device, error) {
	rows, err := r.db.Query(ctx, findDevicesByLoginSQL, loginID)
	if err != nil {
		slog.Error("Failed to find devices by login", "err", err, "loginID", loginID)
		return nil, fmt.Errorf("failed to find devices by login: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(
			&device.Fingerprint,
			&device.UserAgent,
			&device.AcceptHeaders,
			&device.Timezone,
			&device.ScreenResolution,
			&device.LastLoginAt,
			&device.CreatedAt,
		)
		if err != nil {
			slog.Error("Failed to scan device", "err", err)
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		slog.Error("Error iterating device rows", "err", err)
		return nil, fmt.Errorf("error iterating device rows: %w", err)
	}

	slog.Debug("Found devices for login", "loginID", loginID, "deviceCount", len(devices))
	return devices, nil
}

// UpdateDeviceLastLogin updates the last login time of a device
func (r *PostgresDeviceRepository) UpdateDeviceLastLogin(ctx context.Context, fingerprint string, lastLogin time.Time) (Device, error) {
	row := r.db.QueryRow(ctx, updateDeviceLastLoginSQL, fingerprint, lastLogin)

	var device Device
	err := row.Scan(
		&device.Fingerprint,
		&device.UserAgent,
		&device.AcceptHeaders,
		&device.Timezone,
		&device.ScreenResolution,
		&device.LastLoginAt,
		&device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Device not found for update", "fingerprint", fingerprint)
			return Device{}, errors.New("device not found")
		}
		slog.Error("Failed to update device last login", "err", err, "fingerprint", fingerprint)
		return Device{}, fmt.Errorf("failed to update device last login: %w", err)
	}

	slog.Debug("Device last login updated", "fingerprint", fingerprint, "lastLogin", lastLogin)
	return device, nil
}

// FindLoginDeviceByFingerprintAndLoginID returns the login-device link for a specific fingerprint and login ID
func (r *PostgresDeviceRepository) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (*LoginDevice, error) {
	row := r.db.QueryRow(ctx, findLoginDeviceByFingerprintAndLoginIDSQL, fingerprint, loginID)

	var loginDevice LoginDevice
	var deletedAt pgtype.Timestamp
	err := row.Scan(
		&loginDevice.ID,
		&loginDevice.LoginID,
		&loginDevice.Fingerprint,
		&loginDevice.LinkedAt,
		&loginDevice.ExpiresAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Debug("Login device link not found", "fingerprint", fingerprint, "loginID", loginID)
			return nil, fmt.Errorf("login device not found for fingerprint %s and login ID %s", fingerprint, loginID)
		}
		slog.Error("Failed to find login device", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return nil, fmt.Errorf("failed to find login device: %w", err)
	}

	// Convert pgtype.Timestamp to time.Time if valid
	if deletedAt.Valid {
		loginDevice.DeletedAt = deletedAt.Time
	}

	slog.Debug("Found login device link", "fingerprint", fingerprint, "loginID", loginID,
		"linkedAt", loginDevice.LinkedAt.Format(time.RFC3339),
		"expiresAt", loginDevice.ExpiresAt.Format(time.RFC3339))
	return &loginDevice, nil
}

// LinkLoginToDevice links a login to a device
func (r *PostgresDeviceRepository) LinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) (LoginDevice, error) {
	// First, check if the device exists
	_, err := r.GetDeviceByFingerprint(ctx, fingerprint)
	if err != nil {
		slog.Error("Device not found for linking", "err", err, "fingerprint", fingerprint)
		return LoginDevice{}, fmt.Errorf("device not found: %w", err)
	}

	// Check if a link already exists and is not deleted
	existingLink, err := r.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	if err == nil && existingLink != nil && existingLink.DeletedAt.IsZero() {
		// Link already exists and is not deleted
		if existingLink.IsExpired() {
			// If the link is expired, update the expiry date
			expiryDate := CalculateExpiryDate(DefaultDeviceExpiryDays)
			
			row := r.db.QueryRow(ctx, updateLoginDeviceExpirySQL, fingerprint, loginID, expiryDate)
			
			var loginDevice LoginDevice
			var deletedAt pgtype.Timestamp
			err := row.Scan(
				&loginDevice.ID,
				&loginDevice.LoginID,
				&loginDevice.Fingerprint,
				&loginDevice.LinkedAt,
				&loginDevice.ExpiresAt,
				&deletedAt,
			)
			if err != nil {
				slog.Error("Failed to update expired link", "err", err, "fingerprint", fingerprint, "loginID", loginID)
				return LoginDevice{}, fmt.Errorf("failed to update expired link: %w", err)
			}
			
			slog.Debug("Updated expired device link", "fingerprint", fingerprint, "loginID", loginID,
				"expiryDate", expiryDate.Format(time.RFC3339))
			return loginDevice, nil
		}
		
		// Link exists and is not expired, return it
		slog.Debug("Device link already exists", "fingerprint", fingerprint, "loginID", loginID)
		return *existingLink, nil
	}

	// Create a new link
	expiryDate := CalculateExpiryDate(DefaultDeviceExpiryDays)
	
	row := r.db.QueryRow(ctx, createLoginDeviceSQL,
		loginID,
		fingerprint,
		time.Now().UTC(),
		expiryDate,
	)
	
	var loginDevice LoginDevice
	var deletedAt pgtype.Timestamp
	err = row.Scan(
		&loginDevice.ID,
		&loginDevice.LoginID,
		&loginDevice.Fingerprint,
		&loginDevice.LinkedAt,
		&loginDevice.ExpiresAt,
		&deletedAt,
	)
	if err != nil {
		slog.Error("Failed to create device link", "err", err, "fingerprint", fingerprint, "loginID", loginID)
		return LoginDevice{}, fmt.Errorf("failed to create device link: %w", err)
	}
	
	// Convert pgtype.Timestamp to time.Time if valid
	if deletedAt.Valid {
		loginDevice.DeletedAt = deletedAt.Time
	}
	
	slog.Debug("Created new device link", "fingerprint", fingerprint, "loginID", loginID,
		"expiry", loginDevice.ExpiresAt.Format(time.RFC3339))
	return loginDevice, nil
}

// UnlinkLoginToDevice removes the link between a login and a device
func (r *PostgresDeviceRepository) UnlinkLoginToDevice(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	result, err := r.db.Exec(ctx, unlinkLoginDeviceSQL, fingerprint, loginID, time.Now().UTC())
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
