package profile

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/exp/slog"
)

func containerLog(ctx context.Context, container testcontainers.Container) {
	// Retrieve logs
	logs, err := container.Logs(ctx)
	if err != nil {
		slog.Error("Failed to get container logs:", "err", err)
	}
	defer logs.Close()

	// Process and display logs
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		fmt.Println(scanner.Text()) // Print each log line
	}

	// Check for scanning errors
	if err := scanner.Err(); err != nil {
		slog.Error("Error reading logs", "err", err)
	}
}

func setupTestDatabase(t *testing.T) (*pgxpool.Pool, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	dbName := "idm_db"
	dbUser := "idm"
	dbPassword := "pwd"

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("../../migrations", "idm_db.sql")),
		// postgres.WithConfigFile(filepath.Join("testdata", "my-postgres.conf")),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(t, err)
	if err != nil {
		slog.Error("Failed to start container:", "err", err)
	}

	// containerLog(ctx, container)

	// Generate the connection string
	connString, err := container.ConnectionString(ctx)
	fmt.Println("Connection string:", connString)
	require.NoError(t, err)

	// Create connection pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return pool, cleanup
}

// Mock implementation of profiledb.Queries
type mockQueries struct {
	mock.Mock
}

func (m *mockQueries) GetUserByUUID(ctx context.Context, uuid uuid.UUID) (profiledb.User, error) {
	args := m.Called(ctx, uuid)
	return args.Get(0).(profiledb.User), args.Error(1)
}

func (m *mockQueries) UpdateUserPassword(ctx context.Context, arg profiledb.UpdateUserPasswordParams) error {
	args := m.Called(ctx, arg)
	return args.Error(0)
}

func TestUpdatePassword(t *testing.T) {
	// Create test UUID
	userUUID := uuid.New()

	// Test cases
	tests := []struct {
		name          string
		params        UpdatePasswordParams
		setupMock     func(*mockQueries)
		expectedError string
	}{
		{
			name: "successful password update",
			params: UpdatePasswordParams{
				UserUUID:        userUUID,
				CurrentPassword: "oldpass",
				NewPassword:     "newpass",
			},
			setupMock: func(m *mockQueries) {
				// Mock GetUserByUUID
				m.On("GetUserByUUID", mock.Anything, userUUID).Return(profiledb.User{
					Uuid:     userUUID,
					Password: []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), // hash for "oldpass"
				}, nil)

				// Mock UpdateUserPassword
				m.On("UpdateUserPassword", mock.Anything, mock.MatchedBy(func(arg profiledb.UpdateUserPasswordParams) bool {
					return arg.Uuid == userUUID
				})).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "user not found",
			params: UpdatePasswordParams{
				UserUUID:        userUUID,
				CurrentPassword: "oldpass",
				NewPassword:     "newpass",
			},
			setupMock: func(m *mockQueries) {
				m.On("GetUserByUUID", mock.Anything, userUUID).Return(profiledb.User{}, assert.AnError)
			},
			expectedError: "user not found",
		},
		{
			name: "invalid current password",
			params: UpdatePasswordParams{
				UserUUID:        userUUID,
				CurrentPassword: "wrongpass",
				NewPassword:     "newpass",
			},
			setupMock: func(m *mockQueries) {
				m.On("GetUserByUUID", mock.Anything, userUUID).Return(profiledb.User{
					Uuid:     userUUID,
					Password: []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), // hash for "oldpass"
				}, nil)
			},
			expectedError: "invalid current password",
		},
		{
			name: "database error during update",
			params: UpdatePasswordParams{
				UserUUID:        userUUID,
				CurrentPassword: "oldpass",
				NewPassword:     "newpass",
			},
			setupMock: func(m *mockQueries) {
				// Mock GetUserByUUID
				m.On("GetUserByUUID", mock.Anything, userUUID).Return(profiledb.User{
					Uuid:     userUUID,
					Password: []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), // hash for "oldpass"
				}, nil)

				// Mock UpdateUserPassword with error
				m.On("UpdateUserPassword", mock.Anything, mock.MatchedBy(func(arg profiledb.UpdateUserPasswordParams) bool {
					return arg.Uuid == userUUID
				})).Return(assert.AnError)
			},
			expectedError: "failed to update password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock and service
			queries := new(mockQueries)
			service := NewProfileService(queries)

			// Setup mock expectations
			tt.setupMock(queries)

			// Call the method
			err := service.UpdatePassword(context.Background(), tt.params)

			// Assert expectations
			queries.AssertExpectations(t)

			// Check error
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
