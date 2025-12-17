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
	"github.com/tendant/simple-idm/pkg/config"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
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

// PasswordComplexityConfig is now defined in pkg/config package
type PasswordComplexityConfig = config.PasswordComplexityConfig

type Config struct {
	IdmDbConfig              IdmDbConfig
	PasswordComplexityConfig PasswordComplexityConfig
}

type UserInfo struct {
	Email    string
	Username string
	Password string
	RoleName string
}

func main() {
	// Parse command line arguments
	username := flag.String("username", "", "Username for the new user (required)")
	password := flag.String("password", "", "Password for the new user (required)")
	roleName := flag.String("role", "", "Role to assign to the user (required)")
	email := flag.String("email", "", "Email for the new user (required)")
	flag.Parse()

	// Validate required arguments
	if *username == "" || *password == "" || *roleName == "" || *email == "" {
		fmt.Println("Error: username, password, role, and email are required")
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
	iamQueries := iamdb.New(pool)

	// Create password policy and manager
	passwordPolicy := config.PasswordComplexityConfig.ToPasswordPolicy()
	passwordManager := login.NewPasswordManager(loginQueries)
	policyChecker := login.NewDefaultPasswordPolicyChecker(passwordPolicy, nil)
	passwordManager.WithPolicyChecker(policyChecker)

	// Create services
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	loginsService := logins.NewLoginsService(loginsRepo, loginQueries, &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	})
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)
	iamRepo := iam.NewPostgresIamRepository(iamQueries)
	iamService := iam.NewIamService(iamRepo)

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

	// Create the role if it doesn't exist
	if !roleFound {
		slog.Info("Role not found, creating new role", "role", *roleName)
		roleID, err = roleService.CreateRole(context.Background(), *roleName)
		if err != nil {
			slog.Error("Failed to create role", "error", err)
			os.Exit(1)
		}
		slog.Info("Role created successfully", "role", *roleName, "id", roleID)
	} else {
		slog.Info("Using existing role", "role", *roleName, "id", roleID)
	}

	// Create the login record
	slog.Info("Creating login record", "username", *username)
	login, err := loginsService.CreateLogin(context.Background(), logins.LoginCreateRequest{
		Username: *username,
		Password: *password,
	}, "init-user-cmd")
	if err != nil {
		slog.Error("Failed to create login record", "error", err)
		os.Exit(1)
	}

	// We don't need to parse the login ID as the CreateUser method accepts it as a string

	// Create the user record and associate with login
	slog.Info("Creating user record", "email", *email)
	userWithRoles, err := iamService.CreateUser(
		context.Background(),
		*email,
		*username,
		*username, // Using username as name if no separate name is provided
		[]uuid.UUID{roleID},
		login.ID,
	)
	if err != nil {
		slog.Error("Failed to create user record", "error", err)
		os.Exit(1)
	}

	// Commit the transaction
	err = tx.Commit(context.Background())
	if err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		os.Exit(1)
	}

	slog.Info("User created successfully", "username", *username, "email", *email, "role", *roleName, "login_id", login.ID, "user_id", userWithRoles.ID)
}
