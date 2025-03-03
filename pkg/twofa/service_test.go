package twofa

import (
	"context"
	"log"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

// func containerLog(ctx context.Context, container testcontainers.Container) {
// 	// Retrieve logs
// 	logs, err := container.Logs(ctx)
// 	if err != nil {
// 		slog.Error("Failed to get container logs:", "err", err)
// 	}
// 	defer logs.Close()

// 	// Process and display logs
// 	scanner := bufio.NewScanner(logs)
// 	for scanner.Scan() {
// 		fmt.Println(scanner.Text()) // Print each log line
// 	}

// 	// Check for scanning errors
// 	if err := scanner.Err(); err != nil {
// 		slog.Error("Error reading logs", "err", err)
// 	}
// }

// func setupTestDatabase(t *testing.T) (*pgxpool.Pool, func()) {
// 	ctx := context.Background()

// 	// Create PostgreSQL container
// 	dbName := "idm_db"
// 	dbUser := "idmconn"
// 	dbPassword := "pwd"

// 	container, err := postgres.Run(ctx,
// 		"postgres:16-alpine",
// 		postgres.WithInitScripts(filepath.Join("../../migrations", "idm_db.sql")),
// 		// postgres.WithConfigFile(filepath.Join("testdata", "my-postgres.conf")),
// 		postgres.WithDatabase(dbName),
// 		postgres.WithUsername(dbUser),
// 		postgres.WithPassword(dbPassword),
// 		testcontainers.WithWaitStrategy(
// 			wait.ForLog("database system is ready to accept connections").
// 				WithOccurrence(2).
// 				WithStartupTimeout(5*time.Second)),
// 	)
// 	require.NoError(t, err)
// 	if err != nil {
// 		slog.Error("Failed to start container:", "err", err)
// 	}

// 	containerLog(ctx, container)

// 	// Generate the connection string
// 	connString, err := container.ConnectionString(ctx)
// 	fmt.Println("Connection string:", connString)
// 	require.NoError(t, err)

// 	// Create connection pool
// 	poolConfig, err := pgxpool.ParseConfig(connString)
// 	require.NoError(t, err)

// 	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
// 	require.NoError(t, err)

// 	cleanup := func() {
// 		pool.Close()
// 		if err := container.Terminate(ctx); err != nil {
// 			t.Logf("failed to terminate container: %v", err)
// 		}
// 	}

// 	return pool, cleanup
// }

var (
	dbPool *pgxpool.Pool
)

func setup() {
	var err error
	connStr := "postgres://idm:pwd@localhost:5432/idm_db"
	dbPool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
}

func teardown() {
	dbPool.Close()
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetTwoFactorSecretByLoginUuid(t *testing.T) {
	// Setup test database
	// pool, cleanup := setupTestDatabase(t)
	// defer cleanup()
	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, nil)

	// Create a test user with a known password
	ctx := context.Background()
	loginUuid := uuid.MustParse("d315f240-ccd1-4afd-b6e6-b5fba6084f74")

	twofaSecret, err := service.GetTwoFactorSecretByLoginId(ctx, loginUuid, TWO_FACTOR_TYPE_EMAIL)

	require.NoError(t, err)
	// slog.Info("twofaSecret", "secret", twofaSecret)
	require.NotEmpty(t, twofaSecret)
}

func TestInitTwoFa(t *testing.T) {
	notificationManager, err := notice.NewNotificationManager("http://localhost:3000", notification.SMTPConfig{
		Host:     "localhost",
		Port:     1025,
		Username: "noreply@example.com",
		Password: "pwd",
		From:     "noreply@example.com",
		NoTLS:    true,
	})
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, notificationManager)

	err = service.SendTwoFaNotification(context.Background(), uuid.MustParse("cf9eca06-ecd3-4fd8-a291-a78d4f340ce8"), "email", "admin@example.com")
	require.NoError(t, err)
}

func TestEnableTwoFactor(t *testing.T) {
	// Setup test database
	// pool, cleanup := setupTestDatabase(t)
	// defer cleanup()
	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, nil)

	// Call the EnableTwoFactor method
	err := service.EnableTwoFactor(context.Background(), uuid.MustParse("d315f240-ccd1-4afd-b6e6-b5fba6084f74"), "email")

	// Check the result
	require.NoError(t, err)
}

func TestDisableTwoFactor(t *testing.T) {
	// Setup test database
	// pool, cleanup := setupTestDatabase(t)
	// defer cleanup()
	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, nil)

	// Call the DisableTwoFactor method
	err := service.DisableTwoFactor(context.Background(), uuid.MustParse("cf9eca06-ecd3-4fd8-a291-a78d4f340ce8"), "email")

	// Check the result
	require.NoError(t, err)

}

func TestValidate2faPasscode(t *testing.T) {
	notificationManager, err := notice.NewNotificationManager("http://localhost:3000", notification.SMTPConfig{
		Host:     "localhost",
		Port:     1025,
		Username: "noreply@example.com",
		Password: "pwd",
		From:     "noreply@example.com",
		NoTLS:    true,
	})
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, notificationManager)

	res, err := service.Validate2faPasscode(context.Background(), uuid.MustParse("cf9eca06-ecd3-4fd8-a291-a78d4f340ce8"), "email", "123456")

	assert.NoError(t, err)
	assert.False(t, res)

	res, err = service.Validate2faPasscode(context.Background(), uuid.MustParse("cf9eca06-ecd3-4fd8-a291-a78d4f340ce8"), "email", "538684")
	assert.NoError(t, err)
	assert.True(t, res)

}

func TestFindEnabledTwoFAs(t *testing.T) {
	notificationManager, err := notice.NewNotificationManager("http://localhost:3000", notification.SMTPConfig{
		Host:     "localhost",
		Port:     1025,
		Username: "noreply@example.com",
		Password: "pwd",
		From:     "noreply@example.com",
		NoTLS:    true,
	})
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	setup()

	// Create queries and service
	queries := twofadb.New(dbPool)
	service := NewTwoFaService(queries, notificationManager)

	res, err := service.FindEnabledTwoFAs(context.Background(), uuid.MustParse("98d38598-9e56-415a-aab3-7c8c72a2a1a0"))

	require.NoError(t, err)
	require.NotEmpty(t, res)

	slog.Info("res", "res", res[0])
}
