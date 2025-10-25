package twofa

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

// TwoFAEntity represents a 2FA record without database-specific types
type TwoFAEntity struct {
	ID               uuid.UUID
	LoginID          uuid.UUID
	TwoFactorSecret  string
	SecretValid      bool
	TwoFactorType    string
	TypeValid        bool
	TwoFactorEnabled bool
	EnabledValid     bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	UpdatedAtValid   bool
}

// Create2FAParams represents parameters for creating a 2FA record
type Create2FAParams struct {
	LoginID              uuid.UUID
	TwoFactorSecret      string
	SecretValid          bool
	TwoFactorEnabled     bool
	EnabledValid         bool
	TwoFactorType        string
	TypeValid            bool
	TwoFactorBackupCodes []string
}

// Enable2FAParams represents parameters for enabling 2FA
type Enable2FAParams struct {
	LoginID       uuid.UUID
	TwoFactorType string
}

// Disable2FAParams represents parameters for disabling 2FA
type Disable2FAParams struct {
	LoginID       uuid.UUID
	TwoFactorType string
}

// Delete2FAParams represents parameters for deleting a 2FA record
type Delete2FAParams struct {
	ID            uuid.UUID
	LoginID       uuid.UUID
	TwoFactorType string
}

// Get2FAByIDParams represents parameters for getting 2FA by ID
type Get2FAByIDParams struct {
	ID            uuid.UUID
	LoginID       uuid.UUID
	TwoFactorType string
}

// Get2FAByLoginIDParams represents parameters for getting 2FA by login ID
type Get2FAByLoginIDParams struct {
	LoginID       uuid.UUID
	TwoFactorType string
}

// TwoFARepository defines the interface for 2FA operations
type TwoFARepository interface {
	Create2FAInit(ctx context.Context, params Create2FAParams) (uuid.UUID, error)
	Enable2FA(ctx context.Context, params Enable2FAParams) error
	Disable2FA(ctx context.Context, params Disable2FAParams) error
	Delete2FA(ctx context.Context, params Delete2FAParams) error
	Get2FAByID(ctx context.Context, params Get2FAByIDParams) (TwoFAEntity, error)
	Get2FAByLoginID(ctx context.Context, params Get2FAByLoginIDParams) (TwoFAEntity, error)
	FindTwoFAsByLoginID(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error)
	FindEnabledTwoFAs(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error)
}

// PostgresTwoFARepository implements TwoFARepository using PostgreSQL
type PostgresTwoFARepository struct {
	queries *twofadb.Queries
}

// NewPostgresTwoFARepository creates a new PostgreSQL-based 2FA repository
func NewPostgresTwoFARepository(queries *twofadb.Queries) *PostgresTwoFARepository {
	return &PostgresTwoFARepository{
		queries: queries,
	}
}

// Create2FAInit creates a new 2FA record
func (r *PostgresTwoFARepository) Create2FAInit(ctx context.Context, params Create2FAParams) (uuid.UUID, error) {
	var secret pgtype.Text
	if params.SecretValid {
		secret = pgtype.Text{String: params.TwoFactorSecret, Valid: true}
	}

	var enabled pgtype.Bool
	if params.EnabledValid {
		enabled = pgtype.Bool{Bool: params.TwoFactorEnabled, Valid: true}
	}

	var twoFactorType sql.NullString
	if params.TypeValid {
		twoFactorType = sql.NullString{String: params.TwoFactorType, Valid: true}
	}

	return r.queries.Create2FAInit(ctx, twofadb.Create2FAInitParams{
		LoginID:              params.LoginID,
		TwoFactorSecret:      secret,
		TwoFactorEnabled:     enabled,
		TwoFactorType:        twoFactorType,
		TwoFactorBackupCodes: params.TwoFactorBackupCodes,
	})
}

// Enable2FA enables 2FA for a login
func (r *PostgresTwoFARepository) Enable2FA(ctx context.Context, params Enable2FAParams) error {
	return r.queries.Enable2FA(ctx, twofadb.Enable2FAParams{
		LoginID:       params.LoginID,
		TwoFactorType: sql.NullString{String: params.TwoFactorType, Valid: true},
	})
}

// Disable2FA disables 2FA for a login
func (r *PostgresTwoFARepository) Disable2FA(ctx context.Context, params Disable2FAParams) error {
	return r.queries.Disable2FA(ctx, twofadb.Disable2FAParams{
		LoginID:       params.LoginID,
		TwoFactorType: sql.NullString{String: params.TwoFactorType, Valid: true},
	})
}

// Delete2FA soft deletes a 2FA record
func (r *PostgresTwoFARepository) Delete2FA(ctx context.Context, params Delete2FAParams) error {
	return r.queries.Delete2FA(ctx, twofadb.Delete2FAParams{
		ID:            params.ID,
		LoginID:       params.LoginID,
		TwoFactorType: sql.NullString{String: params.TwoFactorType, Valid: true},
	})
}

// Get2FAByID retrieves a 2FA record by ID
func (r *PostgresTwoFARepository) Get2FAByID(ctx context.Context, params Get2FAByIDParams) (TwoFAEntity, error) {
	row, err := r.queries.Get2FAById(ctx, twofadb.Get2FAByIdParams{
		ID:            params.ID,
		LoginID:       params.LoginID,
		TwoFactorType: sql.NullString{String: params.TwoFactorType, Valid: true},
	})
	if err != nil {
		return TwoFAEntity{}, err
	}

	return TwoFAEntity{
		ID:               row.ID,
		TwoFactorEnabled: row.TwoFactorEnabled.Bool,
		EnabledValid:     row.TwoFactorEnabled.Valid,
	}, nil
}

// Get2FAByLoginID retrieves a 2FA record by login ID and type
func (r *PostgresTwoFARepository) Get2FAByLoginID(ctx context.Context, params Get2FAByLoginIDParams) (TwoFAEntity, error) {
	row, err := r.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID:       params.LoginID,
		TwoFactorType: sql.NullString{String: params.TwoFactorType, Valid: true},
	})
	if err != nil {
		return TwoFAEntity{}, err
	}

	return TwoFAEntity{
		ID:               row.ID,
		LoginID:          row.LoginID,
		TwoFactorSecret:  row.TwoFactorSecret.String,
		SecretValid:      row.TwoFactorSecret.Valid,
		TwoFactorEnabled: row.TwoFactorEnabled.Bool,
		EnabledValid:     row.TwoFactorEnabled.Valid,
	}, nil
}

// FindTwoFAsByLoginID retrieves all 2FA records for a login
func (r *PostgresTwoFARepository) FindTwoFAsByLoginID(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error) {
	rows, err := r.queries.FindTwoFAsByLoginId(ctx, loginID)
	if err != nil {
		return nil, err
	}

	entities := make([]TwoFAEntity, 0, len(rows))
	for _, row := range rows {
		entities = append(entities, TwoFAEntity{
			ID:               row.ID,
			LoginID:          row.LoginID,
			TwoFactorType:    row.TwoFactorType.String,
			TypeValid:        row.TwoFactorType.Valid,
			TwoFactorEnabled: row.TwoFactorEnabled.Bool,
			EnabledValid:     row.TwoFactorEnabled.Valid,
			CreatedAt:        row.CreatedAt,
			UpdatedAt:        row.UpdatedAt.Time,
			UpdatedAtValid:   row.UpdatedAt.Valid,
		})
	}

	return entities, nil
}

// FindEnabledTwoFAs retrieves all enabled 2FA records for a login
func (r *PostgresTwoFARepository) FindEnabledTwoFAs(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error) {
	rows, err := r.queries.FindEnabledTwoFAs(ctx, loginID)
	if err != nil {
		return nil, err
	}

	entities := make([]TwoFAEntity, 0, len(rows))
	for _, row := range rows {
		entities = append(entities, TwoFAEntity{
			ID:               row.ID,
			LoginID:          row.LoginID,
			TwoFactorType:    row.TwoFactorType.String,
			TypeValid:        row.TwoFactorType.Valid,
			TwoFactorEnabled: row.TwoFactorEnabled.Bool,
			EnabledValid:     row.TwoFactorEnabled.Valid,
			CreatedAt:        row.CreatedAt,
		})
	}

	return entities, nil
}
