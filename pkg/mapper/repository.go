package mapper

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
)

// UserEntity represents a user without database-specific types
type UserEntity struct {
	ID             uuid.UUID
	Name           string
	NameValid      bool
	Email          string
	Phone          string
	PhoneValid     bool
	CreatedAt      time.Time
	LastModifiedAt time.Time
	LoginID        uuid.UUID
	LoginIDValid   bool
	Groups         []string
	Roles          []string
}

// MapperRepository defines the interface for user-login mapping operations
type MapperRepository interface {
	GetUsersByLoginID(ctx context.Context, loginID uuid.UUID, includeGroups bool) ([]UserEntity, error)
	GetUserByUserID(ctx context.Context, userID uuid.UUID, includeGroups bool) (UserEntity, error)
	FindUsernamesByEmail(ctx context.Context, email string) ([]string, error)
}

// PostgresMapperRepository implements MapperRepository using PostgreSQL
type PostgresMapperRepository struct {
	queries *mapperdb.Queries
}

// NewPostgresMapperRepository creates a new PostgreSQL-based mapper repository
func NewPostgresMapperRepository(queries *mapperdb.Queries) *PostgresMapperRepository {
	return &PostgresMapperRepository{
		queries: queries,
	}
}

// GetUsersByLoginID retrieves all users linked to a login ID
func (r *PostgresMapperRepository) GetUsersByLoginID(ctx context.Context, loginID uuid.UUID, includeGroups bool) ([]UserEntity, error) {
	nullLoginID := uuid.NullUUID{UUID: loginID, Valid: true}

	if includeGroups {
		rows, err := r.queries.GetUsersByLoginIdWithGroups(ctx, nullLoginID)
		if err != nil {
			return nil, err
		}
		return convertGetUsersByLoginIdWithGroupsRows(rows), nil
	}

	rows, err := r.queries.GetUsersByLoginId(ctx, nullLoginID)
	if err != nil {
		return nil, err
	}
	return convertGetUsersByLoginIdRows(rows), nil
}

// GetUserByUserID retrieves a user by user ID
func (r *PostgresMapperRepository) GetUserByUserID(ctx context.Context, userID uuid.UUID, includeGroups bool) (UserEntity, error) {
	if includeGroups {
		row, err := r.queries.GetUserWithGroupsAndRoles(ctx, userID)
		if err != nil {
			return UserEntity{}, err
		}
		return convertGetUserWithGroupsAndRolesRow(row), nil
	}

	row, err := r.queries.GetUserById(ctx, userID)
	if err != nil {
		return UserEntity{}, err
	}
	return convertGetUserByIdRow(row), nil
}

// FindUsernamesByEmail retrieves all usernames associated with an email
func (r *PostgresMapperRepository) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	nullStrings, err := r.queries.FindUsernamesByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	usernames := make([]string, 0, len(nullStrings))
	for _, ns := range nullStrings {
		if ns.Valid {
			usernames = append(usernames, ns.String)
		}
	}
	return usernames, nil
}

// Conversion helpers

func convertGetUsersByLoginIdWithGroupsRows(rows []mapperdb.GetUsersByLoginIdWithGroupsRow) []UserEntity {
	entities := make([]UserEntity, len(rows))
	for i, row := range rows {
		entities[i] = UserEntity{
			ID:             row.ID,
			Name:           row.Name.String,
			NameValid:      row.Name.Valid,
			Email:          row.Email,
			Phone:          row.Phone.String,
			PhoneValid:     row.Phone.Valid,
			CreatedAt:      row.CreatedAt,
			LastModifiedAt: row.LastModifiedAt,
			Groups:         convertInterfaceToStringSlice(row.Groups),
			Roles:          convertInterfaceToStringSlice(row.Roles),
		}
	}
	return entities
}

func convertGetUsersByLoginIdRows(rows []mapperdb.GetUsersByLoginIdRow) []UserEntity {
	entities := make([]UserEntity, len(rows))
	for i, row := range rows {
		entities[i] = UserEntity{
			ID:             row.ID,
			Name:           row.Name.String,
			NameValid:      row.Name.Valid,
			Email:          row.Email,
			Phone:          row.Phone.String,
			PhoneValid:     row.Phone.Valid,
			CreatedAt:      row.CreatedAt,
			LastModifiedAt: row.LastModifiedAt,
			Groups:         []string{},
			Roles:          convertInterfaceToStringSlice(row.Roles),
		}
	}
	return entities
}

func convertGetUserWithGroupsAndRolesRow(row mapperdb.GetUserWithGroupsAndRolesRow) UserEntity {
	return UserEntity{
		ID:             row.ID,
		Name:           row.Name.String,
		NameValid:      row.Name.Valid,
		Email:          row.Email,
		Phone:          row.Phone.String,
		PhoneValid:     row.Phone.Valid,
		CreatedAt:      row.CreatedAt,
		LastModifiedAt: row.LastModifiedAt,
		LoginID:        row.LoginID.UUID,
		LoginIDValid:   row.LoginID.Valid,
		Groups:         convertInterfaceToStringSlice(row.Groups),
		Roles:          convertInterfaceToStringSlice(row.Roles),
	}
}

func convertGetUserByIdRow(row mapperdb.GetUserByIdRow) UserEntity {
	return UserEntity{
		ID:             row.ID,
		Name:           row.Name.String,
		NameValid:      row.Name.Valid,
		Email:          row.Email,
		Phone:          row.Phone.String,
		PhoneValid:     row.Phone.Valid,
		CreatedAt:      row.CreatedAt,
		LastModifiedAt: row.LastModifiedAt,
		LoginID:        row.LoginID.UUID,
		LoginIDValid:   row.LoginID.Valid,
		Groups:         []string{},
		Roles:          convertInterfaceToStringSlice(row.Roles),
	}
}

// convertInterfaceToStringSlice converts PostgreSQL array (interface{}) to []string
func convertInterfaceToStringSlice(val interface{}) []string {
	if val == nil {
		return []string{}
	}

	// Handle []interface{} (common PostgreSQL array return type)
	if arr, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	// Handle []string directly
	if arr, ok := val.([]string); ok {
		return arr
	}

	// Handle sql.NullString array
	if arr, ok := val.([]sql.NullString); ok {
		result := make([]string, 0, len(arr))
		for _, ns := range arr {
			if ns.Valid {
				result = append(result, ns.String)
			}
		}
		return result
	}

	return []string{}
}
