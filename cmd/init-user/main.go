package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/ilyakaznacheev/cleanenv"
	dbutils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/role"
	"github.com/tendant/simple-idm/pkg/role/roledb"
)

type IdmDbConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"postgres.orb.local"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"powercard_db"`
	User     string `env:"IDM_PG_USER" env-default:"bat"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
}

func (d IdmDbConfig) toDbConfig() dbutils.DbConfig {
	return dbutils.DbConfig{
		Host:     d.Host,
		Port:     d.Port,
		Database: d.Database,
		User:     d.User,
		Password: d.Password,
	}
}

type PasswordComplexityConfig struct {
	RequiredDigit           bool `env:"PASSWORD_COMPLEXITY_REQUIRE_DIGIT" env-default:"true"`
	RequiredLowercase       bool `env:"PASSWORD_COMPLEXITY_REQUIRE_LOWERCASE" env-default:"true"`
	RequiredNonAlphanumeric bool `env:"PASSWORD_COMPLEXITY_REQUIRE_NON_ALPHANUMERIC" env-default:"true"`
	RequiredUppercase       bool `env:"PASSWORD_COMPLEXITY_REQUIRE_UPPERCASE" env-default:"true"`
	RequiredLength          int  `env:"PASSWORD_COMPLEXITY_REQUIRED_LENGTH" env-default:"8"`
	DisallowCommonPwds      bool `env:"PASSWORD_COMPLEXITY_DISALLOW_COMMON_PWDS" env-default:"true"`
	MaxRepeatedChars        int  `env:"PASSWORD_COMPLEXITY_MAX_REPEATED_CHARS" env-default:"3"`
	HistoryCheckCount       int  `env:"PASSWORD_COMPLEXITY_HISTORY_CHECK_COUNT" env-default:"5"`
	ExpirationDays          int  `env:"PASSWORD_COMPLEXITY_EXPIRATION_DAYS" env-default:"90"`
}

type Config struct {
	IdmDbConfig              IdmDbConfig
	PasswordComplexityConfig PasswordComplexityConfig
}

func main() {
	// Parse command line arguments
	username := flag.String("username", "", "Username for the new user (required)")
	password := flag.String("password", "", "Password for the new user (required)")
	roleName := flag.String("role", "", "Role to assign to the user (required)")
	flag.Parse()

	// Validate required arguments
	if *username == "" || *password == "" || *roleName == "" {
		fmt.Println("Error: username, password, and role are required")
		flag.Usage()
		os.Exit(1)
	}

	// Create a logger with source enabled
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true, // Enables line number & file path
	}))

	// Set the logger as the default
	slog.SetDefault(logger)

	// Load configuration from environment variables
	config := Config{}
	cleanenv.ReadEnv(&config)

	// Connect to the database
	dbConfig := config.IdmDbConfig.toDbConfig()
	pool, err := dbutils.NewDbPool(context.Background(), dbConfig)
	if err != nil {
		slog.Error("Failed creating dbpool", "db", dbConfig.Database, "host", dbConfig.Host, "port", dbConfig.Port, "user", dbConfig.User)
		os.Exit(1)
	}

	// Initialize database queries
	loginQueries := logindb.New(pool)
	loginsQueries := loginsdb.New(pool)
	roleQueries := roledb.New(pool)

	// Create password policy and manager
	passwordPolicy := createPasswordPolicy(&config.PasswordComplexityConfig)
	passwordManager := login.NewPasswordManager(loginQueries)
	policyChecker := login.NewDefaultPasswordPolicyChecker(passwordPolicy, nil)
	passwordManager.WithPolicyChecker(policyChecker)

	// Create services
	loginsService := logins.NewLoginsService(loginsQueries, loginQueries, &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	})
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)

	// Start a transaction
	tx, err := pool.Begin(context.Background())
	if err != nil {
		slog.Error("Failed to start transaction", "error", err)
		os.Exit(1)
	}

	// Defer transaction rollback - will be ignored if transaction is committed
	defer tx.Rollback(context.Background())

	// Find the role by name
	roles, err := roleService.FindRoles(context.Background())
	if err != nil {
		slog.Error("Failed to fetch roles", "error", err)
		os.Exit(1)
	}

	// Find the role ID by name
	var roleID uuid.UUID
	roleFound := false
	for _, r := range roles {
		if r.Name == *roleName {
			roleID = r.ID
			roleFound = true
			break
		}
	}

	if !roleFound {
		slog.Error("Role not found", "role", *roleName)
		os.Exit(1)
	}

	// Create the user
	slog.Info("Creating user", "username", *username)
	user, err := loginsService.CreateLogin(context.Background(), logins.LoginCreateRequest{
		Username: *username,
		Password: *password,
	}, "init-user-cmd")
	if err != nil {
		slog.Error("Failed to create user", "error", err)
		os.Exit(1)
	}

	// Assign the role to the user
	slog.Info("Assigning role to user", "role", *roleName, "username", *username)
	userID, err := uuid.Parse(user.ID)
	if err != nil {
		slog.Error("Failed to parse user ID", "error", err)
		os.Exit(1)
	}

	err = roleService.AddUserToRole(context.Background(), roleID, userID, *username)
	if err != nil {
		slog.Error("Failed to assign role to user", "error", err)
		os.Exit(1)
	}

	// Commit the transaction
	err = tx.Commit(context.Background())
	if err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		os.Exit(1)
	}

	slog.Info("User created successfully", "username", *username, "role", *roleName, "id", user.ID)
}

func createPasswordPolicy(config *PasswordComplexityConfig) *login.PasswordPolicy {
	return &login.PasswordPolicy{
		RequireDigit:       config.RequiredDigit,
		RequireLowercase:   config.RequiredLowercase,
		RequireSpecialChar: config.RequiredNonAlphanumeric,
		RequireUppercase:   config.RequiredUppercase,
		MinLength:          config.RequiredLength,
		DisallowCommonPwds: config.DisallowCommonPwds,
		MaxRepeatedChars:   config.MaxRepeatedChars,
		HistoryCheckCount:  config.HistoryCheckCount,
		ExpirationDays:     config.ExpirationDays,
	}
}
