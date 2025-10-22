package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/jwks"

	// "github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/oidc"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/wellknown"
)

// In-memory user storage for demo purposes
type User struct {
	ID       string
	Username string
	Password string
	Email    string
	Name     string
}

type Session struct {
	UserID    string
	ExpiresAt time.Time
}

var (
	// Demo users
	users = map[string]*User{
		"demo": {
			ID:       uuid.New().String(),
			Username: "demo",
			Password: "password",
			Email:    "demo@example.com",
			Name:     "Demo User",
		},
		"alice": {
			ID:       uuid.New().String(),
			Username: "alice",
			Password: "password",
			Email:    "alice@example.com",
			Name:     "Alice Johnson",
		},
	}

	// In-memory sessions
	sessions      = make(map[string]*Session)
	sessionsMutex sync.RWMutex
)

// Simple user mapper implementation
// type SimpleUserMapper struct{}

// func (m *SimpleUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (*mapper.UserWithGroups, error) {
// 	// Find user by UUID
// 	for _, user := range users {
// 		if user.ID == userID.String() {
// 			return &mapper.UserWithGroups{
// 				UserID:      userID,
// 				DisplayName: user.Name,
// 				UserInfo: mapper.UserInfo{
// 					Email:         user.Email,
// 					EmailVerified: true,
// 				},
// 				Groups: []string{"users", "demo"},
// 			}, nil
// 		}
// 	}
// 	return nil, fmt.Errorf("user not found")
// }

func main() {
	slog.Info("Starting OIDC Server Demo")

	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	// Create JWKS service
	jwksService, err := jwks.NewJWKSServiceWithKey(&jwks.KeyPair{
		Kid:        "demo-key-1",
		Alg:        "RS256",
		PrivateKey: privateKey,
	})
	if err != nil {
		log.Fatal("Failed to create JWKS service:", err)
	}

	// Get active signing key
	activeKey, err := jwksService.GetActiveSigningKey()
	if err != nil {
		log.Fatal("Failed to get active signing key:", err)
	}

	// Create RSA token generator
	tokenGenerator := tokengenerator.NewRSATokenGenerator(
		activeKey.PrivateKey,
		activeKey.Kid,
		"http://localhost:4001", // issuer
		"http://localhost:4001", // audience
	)

	// Create in-memory OAuth2 client repository
	clientRepo := oauth2client.NewInMemoryOAuth2ClientRepository()

	// Add demo client
	demoClient := &oauth2client.OAuth2Client{
		ClientID:     "demo-client",
		ClientSecret: "demo-secret",
		RedirectURIs: []string{
			"http://localhost:4002/callback",
			"http://localhost:5173/callback",
		},
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile", "email", "groups"},
		ClientName: "Demo Client Application",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if _, err := clientRepo.CreateClient(context.Background(), demoClient); err != nil {
		log.Fatal("Failed to create demo client:", err)
	}

	clientService := oauth2client.NewClientService(clientRepo)

	// Create OIDC service
	oidcRepository := oidc.NewInMemoryOIDCRepository()
	// userMapper := &SimpleUserMapper{}

	oidcService := oidc.NewOIDCServiceWithOptions(
		oidcRepository,
		clientService,
		oidc.WithTokenGenerator(tokenGenerator),
		oidc.WithBaseURL("http://localhost:4001"),
		oidc.WithLoginURL("http://localhost:4001/login"),
		// oidc.WithUserMapper(userMapper),
		oidc.WithIssuer("http://localhost:4001"),
		oidc.WithTokenExpiration(1*time.Hour),
		oidc.WithCodeExpiration(10*time.Minute),
	)

	// Create router
	r := chi.NewRouter()

	// Well-known endpoints
	wellKnownConfig := wellknown.Config{
		ResourceURI:            "http://localhost:4001",
		AuthorizationServerURI: "http://localhost:4001",
		BaseURL:                "http://localhost:4001",
		Scopes:                 []string{"openid", "profile", "email", "groups"},
		ResourceDocumentation:  "http://localhost:4001",
	}
	wellKnownHandler := wellknown.NewHandler(wellKnownConfig, wellknown.WithJWKSService(jwksService))

	r.Get("/.well-known/openid-configuration", wellKnownHandler.OpenIDConfiguration)
	r.Get("/.well-known/oauth-authorization-server", wellKnownHandler.AuthorizationServerMetadata)
	r.Get("/jwks", wellKnownHandler.JWKS)

	// Web pages (HTML responses)
	r.Get("/", handleHome)
	r.Get("/login", handleLoginPage)
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		handleLoginSubmit(w, r, oidcService)
	})

	// API endpoints
	r.Route("/api/oidc", func(r chi.Router) {
		r.Get("/authorize", func(w http.ResponseWriter, r *http.Request) {
			handleAuthorize(w, r, oidcService)
		})
		r.Post("/token", func(w http.ResponseWriter, r *http.Request) {
			handleToken(w, r)
		})
		r.Get("/userinfo", func(w http.ResponseWriter, r *http.Request) {
			handleUserInfo(w, r, oidcService)
		})
	})

	slog.Info("OIDC Server started", "url", "http://localhost:4001")
	slog.Info("Demo client configured", "client_id", "demo-client", "redirect_uri", "http://localhost:4002/callback")
	slog.Info("Demo users", "users", []string{"demo/password", "alice/password"})

	if err := http.ListenAndServe(":4001", r); err != nil {
		log.Fatal(err)
	}
}

// Web page handlers (pure HTML responses)

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Server Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        h1 { color: #333; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        ul { line-height: 1.8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>OIDC Server Demo</h1>
        <p>This is a demonstration OIDC/OAuth2 Provider server.</p>
    </div>

    <div class="card">
        <h2>Configuration</h2>
        <ul>
            <li><strong>Issuer:</strong> http://localhost:4001</li>
            <li><strong>Authorization Endpoint:</strong> http://localhost:4001/api/oidc/authorize</li>
            <li><strong>Token Endpoint:</strong> http://localhost:4001/api/oidc/token</li>
            <li><strong>UserInfo Endpoint:</strong> http://localhost:4001/api/oidc/userinfo</li>
            <li><strong>JWKS URI:</strong> http://localhost:4001/jwks</li>
        </ul>
    </div>

    <div class="card">
        <h2>Demo Client</h2>
        <ul>
            <li><strong>Client ID:</strong> <code>demo-client</code></li>
            <li><strong>Client Secret:</strong> <code>demo-secret</code></li>
            <li><strong>Redirect URI:</strong> <code>http://localhost:4002/callback</code></li>
        </ul>
    </div>

    <div class="card">
        <h2>Demo Users</h2>
        <ul>
            <li>Username: <code>demo</code> / Password: <code>password</code></li>
            <li>Username: <code>alice</code> / Password: <code>password</code></li>
        </ul>
    </div>

    <div class="card">
        <h2>Discovery Endpoints</h2>
        <ul>
            <li><a href="/.well-known/openid-configuration">OpenID Configuration</a></li>
            <li><a href="/.well-known/oauth-authorization-server">OAuth Authorization Server Metadata</a></li>
            <li><a href="/jwks">JWKS (JSON Web Key Set)</a></li>
        </ul>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("redirect")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Login - OIDC Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .login-card { border: 1px solid #ddd; border-radius: 8px; padding: 30px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input[type="text"], input[type="password"] { width: 100%%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%%; padding: 12px; background: #4285f4; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button:hover { background: #3367d6; }
        .error { color: red; margin-bottom: 15px; }
        .hint { font-size: 12px; color: #888; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>Login</h1>
        <form method="POST" action="/login?redirect=%s">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
                <div class="hint">Try: demo or alice</div>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
                <div class="hint">Password: password</div>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`, url.QueryEscape(returnURL))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request, oidcService *oidc.OIDCService) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	returnURL := r.URL.Query().Get("redirect")

	// Validate credentials
	user, ok := users[username]
	if !ok || user.Password != password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := generateRandomString(32)
	sessionsMutex.Lock()
	sessions[sessionID] = &Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	sessionsMutex.Unlock()

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600,
	})

	// Redirect to return URL or home
	if returnURL != "" {
		http.Redirect(w, r, returnURL, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// API handlers

func handleAuthorize(w http.ResponseWriter, r *http.Request, oidcService *oidc.OIDCService) {
	// Get authorization request parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// Check if user is authenticated
	sessionID, err := r.Cookie("session_id")
	if err != nil || sessionID.Value == "" {
		// Redirect to login
		authURL := r.URL.String()
		loginURL := fmt.Sprintf("/login?redirect=%s", url.QueryEscape("/api/oidc/authorize"+authURL[strings.Index(authURL, "?"):]))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Get session
	sessionsMutex.RLock()
	session, ok := sessions[sessionID.Value]
	sessionsMutex.RUnlock()

	if !ok || session.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Generate authorization code
	var statePtr *string
	if state != "" {
		statePtr = &state
	}

	authCode, err := oidcService.GenerateAuthorizationCode(
		r.Context(),
		clientID,
		redirectURI,
		scope,
		statePtr,
		session.UserID,
	)
	if err != nil {
		slog.Error("Failed to generate authorization code", "error", err)
		http.Error(w, "Failed to generate authorization code", http.StatusInternalServerError)
		return
	}

	// Build callback URL
	callbackURL, err := oidcService.BuildCallbackURL(redirectURI, authCode, statePtr)
	if err != nil {
		slog.Error("Failed to build callback URL", "error", err)
		http.Error(w, "Failed to build callback URL", http.StatusInternalServerError)
		return
	}

	slog.Info("Authorization code generated", "client_id", clientID, "user_id", session.UserID)
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType != "authorization_code" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
		return
	}

	// Validate client credentials
	if clientID != "demo-client" || clientSecret != "demo-secret" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Get OIDC service from context (we'll pass it through the handler)
	// For now, we'll create a simple validation

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "demo_access_token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     "demo_id_token",
		"scope":        "openid profile email",
	})
}

func handleUserInfo(w http.ResponseWriter, r *http.Request, oidcService *oidc.OIDCService) {
	// Get access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Get user info
	userInfo, err := oidcService.GetUserInfo(r.Context(), accessToken)
	if err != nil {
		slog.Error("Failed to get user info", "error", err)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Helper functions

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}
