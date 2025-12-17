// Package main demonstrates running Simple IDM without a database using in-memory repositories.
// This is useful for:
// - Quick development and testing
// - Demo/prototype environments
// - Integration testing
// - Learning the API without database setup
//
// Note: All data is lost when the server stops. For production, use cmd/loginv2 with PostgreSQL.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/tendant/chi-demo/app"
	"github.com/tendant/cors"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	"github.com/tendant/simple-idm/pkg/login"
	loginv2 "github.com/tendant/simple-idm/pkg/login/handler/v2"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/role"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	"github.com/tendant/simple-idm/pkg/signup"
	signupv2 "github.com/tendant/simple-idm/pkg/signup/handler/v2"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtSecret = "inmem-dev-secret-change-in-production"
	baseURL   = "http://localhost:4000"
	issuer    = "inmem-idm"
)

func main() {
	// Setup logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("Starting In-Memory IDM Service (no database required)")
	slog.Info(strings.Repeat("=", 60))

	// Initialize all in-memory repositories
	loginRepo := login.NewInMemoryLoginRepository()
	loginsRepo := logins.NewInMemoryLoginsRepository()
	iamRepo := iam.NewInMemoryIamRepository()
	iamGroupRepo := iam.NewInMemoryIamGroupRepository()
	roleRepo := role.NewInMemoryRoleRepository()
	mapperRepo := mapper.NewInMemoryMapperRepository()

	// Seed initial data
	seedInitialData(loginRepo, loginsRepo, iamRepo, roleRepo, mapperRepo)

	// Create services
	services := createServices(loginRepo, loginsRepo, iamRepo, iamGroupRepo, roleRepo, mapperRepo)

	// Setup HTTP server
	server := app.NewApp(
		app.WithPort(4000),
		app.WithCORS(&cors.Options{
			AllowedOrigins:   []string{"http://localhost:5173", "http://localhost:3000", "http://localhost:4040"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Content-Type", "Authorization"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300,
		}),
	)

	// Setup routes
	setupRoutes(server.R, services)

	slog.Info(strings.Repeat("=", 60))
	slog.Info("In-Memory IDM Service Ready")
	slog.Info("Base URL: " + baseURL)
	slog.Info("")
	slog.Info("Test credentials:")
	slog.Info("  Username: admin@example.com")
	slog.Info("  Password: password123")
	slog.Info("")
	slog.Info("API Endpoints:")
	slog.Info("  POST /api/v2/auth/login     - Login")
	slog.Info("  POST /api/v2/auth/logout    - Logout")
	slog.Info("  GET  /api/idm/users         - List users (auth required)")
	slog.Info("  GET  /api/idm/roles         - List roles (auth required)")
	slog.Info(strings.Repeat("=", 60))

	server.Run()
}

type Services struct {
	loginService       *login.LoginService
	loginFlowService   *loginflow.LoginFlowService
	loginsService      *logins.LoginsService
	iamService         *iam.IamService
	roleService        *role.RoleService
	signupService      *signup.SignupService
	tokenCookieService tokengenerator.TokenCookieService
	jwtAuth            *jwtauth.JWTAuth
}

func createServices(
	loginRepo *login.InMemoryLoginRepository,
	loginsRepo *logins.InMemoryLoginsRepository,
	iamRepo *iam.InMemoryIamRepository,
	iamGroupRepo *iam.InMemoryIamGroupRepository,
	roleRepo *role.InMemoryRoleRepository,
	mapperRepo *mapper.InMemoryMapperRepository,
) *Services {
	// User mapper
	userMapper := mapper.NewDefaultUserMapper(mapperRepo)

	// Login service (no notification manager for in-memory mode)
	loginService := login.NewLoginServiceWithOptions(
		loginRepo,
		login.WithUserMapper(userMapper),
	)

	// Token services (HMAC for simplicity in dev mode)
	hmacTokenGenerator := tokengenerator.NewJwtTokenGenerator(jwtSecret, issuer, baseURL)
	tempTokenGenerator := tokengenerator.NewTempTokenGenerator(jwtSecret, issuer, baseURL)

	tokenService := tokengenerator.NewTokenServiceFromGenerator(
		hmacTokenGenerator,
		tokengenerator.WithTempTokenGenerator(tempTokenGenerator),
		tokengenerator.WithAccessTokenExpiry("15m"),
		tokengenerator.WithRefreshTokenExpiry("24h"),
	)

	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		true,  // httpOnly
		false, // secure (false for local dev)
		http.SameSiteLaxMode,
	)

	// No-op services for 2FA and device (not needed for basic auth)
	twoFaService := twofa.NewNoOpTwoFactorService()
	deviceRepo := device.NewNoOpDeviceRepository()
	deviceService := device.NewDeviceService(deviceRepo)

	// LoginFlow service
	loginFlowService := loginflow.NewLoginFlowService(
		loginService,
		twoFaService,
		deviceService,
		tokenService,
		&tokenCookieService,
		userMapper,
	)

	// IAM service
	iamService := iam.NewIamServiceWithOptions(
		iamRepo,
		iam.WithGroupRepository(iamGroupRepo),
	)

	// Role service
	roleService := role.NewRoleService(roleRepo)

	// Logins service
	loginsService := logins.NewLoginsService(loginsRepo, nil, nil)

	// Signup service
	signupService := signup.NewSignupService(
		signup.WithIamServiceForSignup(iamService),
		signup.WithRoleServiceForSignup(roleService),
		signup.WithLoginServiceForSignup(loginService),
		signup.WithLoginsServiceForSignup(loginsService),
		signup.WithRegistrationEnabledForSignup(true),
		signup.WithDefaultRoleForSignup("user"),
	)

	// JWT auth for middleware
	jwtAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)

	return &Services{
		loginService:       loginService,
		loginFlowService:   loginFlowService,
		loginsService:      loginsService,
		iamService:         iamService,
		roleService:        roleService,
		signupService:      signupService,
		tokenCookieService: tokenCookieService,
		jwtAuth:            jwtAuth,
	}
}

func setupRoutes(r *chi.Mux, services *Services) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// V2 Auth routes (public)
	loginHandlerV2 := loginv2.NewHandle(
		services.loginService,
		services.loginFlowService,
		services.tokenCookieService,
	)
	signupHandlerV2 := signupv2.NewHandle(
		services.signupService,
		services.loginFlowService,
		services.tokenCookieService,
	)

	r.Route("/api/v2/auth", func(r chi.Router) {
		r.Post("/login", loginHandlerV2.Login)
		r.Post("/logout", loginHandlerV2.Logout)
		r.Post("/refresh", loginHandlerV2.RefreshToken)
		r.Post("/signup", signupHandlerV2.Signup)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(services.jwtAuth))
		r.Use(jwtauth.Authenticator(services.jwtAuth))
		r.Use(client.AuthUserMiddleware)

		// IAM routes (user management)
		iamHandle := iamapi.NewHandle(services.iamService)
		r.Mount("/api/idm/users", iamapi.SecureHandler(iamHandle))

		// Role routes
		roleHandle := roleapi.NewHandle(services.roleService)
		r.Mount("/api/idm/roles", roleapi.Handler(roleHandle))
	})
}

func seedInitialData(
	loginRepo *login.InMemoryLoginRepository,
	loginsRepo *logins.InMemoryLoginsRepository,
	iamRepo *iam.InMemoryIamRepository,
	roleRepo *role.InMemoryRoleRepository,
	mapperRepo *mapper.InMemoryMapperRepository,
) {
	slog.Info("Seeding initial data...")

	// Create roles
	adminRoleID := uuid.New()
	userRoleID := uuid.New()

	roleRepo.SeedRole(role.Role{ID: adminRoleID, Name: "admin"})
	roleRepo.SeedRole(role.Role{ID: userRoleID, Name: "user"})
	slog.Info("Created roles", "admin", adminRoleID, "user", userRoleID)

	// Also seed roles in IAM repo (for role lookup)
	iamRepo.SeedRole(iam.Role{ID: adminRoleID, Name: "admin"})
	iamRepo.SeedRole(iam.Role{ID: userRoleID, Name: "user"})

	// Create admin login
	adminLoginID := uuid.New()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	adminLogin := login.LoginEntity{
		ID:            adminLoginID,
		Username:      "admin@example.com",
		UsernameValid: true,
		Password:      hashedPassword,
	}
	loginRepo.SeedLogin(adminLogin, "admin@example.com")
	slog.Info("Created admin login", "id", adminLoginID, "username", "admin@example.com")

	// Create admin user
	adminUserID := uuid.New()
	adminUser := iam.User{
		ID:      adminUserID,
		Email:   "admin@example.com",
		Name:    "Admin User",
		LoginID: &adminLoginID,
	}
	iamRepo.SeedUser(adminUser)
	slog.Info("Created admin user", "id", adminUserID)

	// Assign admin role
	iamRepo.CreateUserRole(nil, iam.UserRoleParams{
		UserID: adminUserID,
		RoleID: adminRoleID,
	})

	// Add to mapper for user lookup
	mapperRepo.AddUser(mapper.UserEntity{
		ID:           adminUserID,
		Email:        "admin@example.com",
		Name:         "Admin User",
		NameValid:    true,
		LoginID:      adminLoginID,
		LoginIDValid: true,
		Roles:        []string{"admin"},
	})

	slog.Info("Initial data seeded successfully")
}
