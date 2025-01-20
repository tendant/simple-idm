package user

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tendant/simple-idm/pkg/user/db"
)

// MockQueries is a mock implementation of the db.Queries interface
type MockQueries struct {
	mock.Mock
}

func (m *MockQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(db.User), args.Error(1)
}

func (m *MockQueries) FindUsers(ctx context.Context) ([]db.FindUsersRow, error) {
	args := m.Called(ctx)
	return args.Get(0).([]db.FindUsersRow), args.Error(1)
}

func (m *MockQueries) FindUsersWithRoles(ctx context.Context) ([]db.FindUsersWithRolesRow, error) {
	args := m.Called(ctx)
	return args.Get(0).([]db.FindUsersWithRolesRow), args.Error(1)
}

func (m *MockQueries) GetUserWithRoles(ctx context.Context, uuid uuid.UUID) (db.GetUserWithRolesRow, error) {
	args := m.Called(ctx, uuid)
	return args.Get(0).(db.GetUserWithRolesRow), args.Error(1)
}

func (m *MockQueries) GetUser(ctx context.Context, uuid uuid.UUID) (db.User, error) {
	args := m.Called(ctx, uuid)
	return args.Get(0).(db.User), args.Error(1)
}

func (m *MockQueries) UpdateUser(ctx context.Context, arg db.UpdateUserParams) (db.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(db.User), args.Error(1)
}

func (m *MockQueries) DeleteUser(ctx context.Context, uuid uuid.UUID) error {
	args := m.Called(ctx, uuid)
	return args.Error(0)
}

func (m *MockQueries) CreateUserRole(ctx context.Context, arg db.CreateUserRoleParams) (db.UserRole, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(db.UserRole), args.Error(1)
}

func (m *MockQueries) DeleteUserRoles(ctx context.Context, userUuid uuid.UUID) error {
	args := m.Called(ctx, userUuid)
	return args.Error(0)
}

func (m *MockQueries) GetUserUUID(ctx context.Context, uuid uuid.UUID) (db.GetUserUUIDRow, error) {
	args := m.Called(ctx, uuid)
	return args.Get(0).(db.GetUserUUIDRow), args.Error(1)
}

func (m *MockQueries) CreateUserRoleBatch(ctx context.Context, arg []db.CreateUserRoleBatchParams) error {
	args := m.Called(ctx, arg)
	return args.Error(0)
}

func (m *MockQueries) WithTx(tx pgx.Tx) *db.Queries {
	args := m.Called(tx)
	return args.Get(0).(*db.Queries)
}

// Implement DBTX interface methods
func (m *MockQueries) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgconn.CommandTag), args.Error(1)
}

func (m *MockQueries) Query(ctx context.Context, sql string, arguments ...interface{}) (pgx.Rows, error) {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgx.Rows), args.Error(1)
}

func (m *MockQueries) QueryRow(ctx context.Context, sql string, arguments ...interface{}) pgx.Row {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgx.Row)
}

func (m *MockQueries) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	args := m.Called(ctx, tableName, columnNames, rowSrc)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQueries) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	return args.Get(0).(pgx.Tx), args.Error(1)
}

func (m *MockQueries) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockQueries) Rollback(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestCreateUser(t *testing.T) {
	mockQueries := &MockQueries{}
	queries := db.New(mockQueries)
	service := NewUserService(queries)
	ctx := context.Background()

	testCases := []struct {
		name      string
		email     string
		userName  string
		roleUuids []uuid.UUID
		mockSetup func()
		wantErr   bool
	}{
		{
			name:     "successful creation",
			email:    "test@example.com",
			userName: "Test User",
			roleUuids: []uuid.UUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			mockSetup: func() {
				// Mock CreateUser
				mockQueries.On("CreateUser", ctx, db.CreateUserParams{
					Email: "test@example.com",
					Name:  sql.NullString{String: "Test User", Valid: true},
				}).Return(db.User{
					Uuid:           uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					Email:          "test@example.com",
					Name:           sql.NullString{String: "Test User", Valid: true},
					CreatedAt:      time.Now(),
					LastModifiedAt: time.Now(),
				}, nil)

				// Mock CreateUserRole
				mockQueries.On("CreateUserRole", ctx, mock.AnythingOfType("db.CreateUserRoleParams")).
					Return(db.UserRole{
						UserUuid: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
						RoleUuid: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
					}, nil)

				// Mock GetUserWithRoles
				mockQueries.On("GetUserWithRoles", ctx, mock.AnythingOfType("uuid.UUID")).
					Return(db.GetUserWithRolesRow{
						Uuid:  uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
						Email: "test@example.com",
						Name:  sql.NullString{String: "Test User", Valid: true},
						Roles: []byte(`[{"name":"TestRole","uuid":"550e8400-e29b-41d4-a716-446655440000"}]`),
					}, nil)
			},
			wantErr: false,
		},
		{
			name:     "empty email",
			email:    "",
			userName: "Test User",
			roleUuids: []uuid.UUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			mockSetup: func() {
				// No mocks needed as it should fail validation
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			if tc.mockSetup != nil {
				tc.mockSetup()
			}

			// Execute test
			user, err := service.CreateUser(ctx, tc.email, tc.userName, tc.roleUuids)

			// Verify results
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.email, user.Email)
				assert.Equal(t, tc.userName, user.Name.String)
				assert.True(t, user.Name.Valid)
			}

			// Verify all mocks were called as expected
			mockQueries.AssertExpectations(t)
		})
	}
}
