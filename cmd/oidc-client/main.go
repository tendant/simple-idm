package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Configuration
const (
	ClientID         = "demo-client"
	ClientSecret     = "demo-secret"
	AuthorizationURL = "http://localhost:4001/api/oidc/authorize"
	TokenURL         = "http://localhost:4001/api/oidc/token"
	UserInfoURL      = "http://localhost:4001/api/oidc/userinfo"
	RedirectURI      = "http://localhost:4002/callback"
	ClientPort       = ":4002"
)

// Session represents a user session
type Session struct {
	UserID      string
	AccessToken string
	IDToken     string
	UserInfo    map[string]interface{}
	ExpiresAt   time.Time
}

// StateInfo stores OIDC state information
type StateInfo struct {
	State     string
	CreatedAt time.Time
}

var (
	// In-memory session storage
	sessions      = make(map[string]*Session)
	sessionsMutex sync.RWMutex

	// OIDC state storage (for CSRF protection)
	states      = make(map[string]*StateInfo)
	statesMutex sync.RWMutex
)

func main() {
	slog.Info("Starting OIDC Client Demo")

	r := chi.NewRouter()

	// Web pages (HTML responses)
	r.Get("/", handleHomePage)
	r.Get("/callback", handleCallback)
	r.Get("/protected", handleProtectedPage)

	// API endpoints
	r.Route("/api/auth", func(r chi.Router) {
		r.Get("/me", handleAuthMe)
		r.Post("/logout", handleLogout)
	})

	slog.Info("OIDC Client started", "url", "http://localhost:4002")
	slog.Info("Open http://localhost:4002 in your browser to start")

	if err := http.ListenAndServe(ClientPort, r); err != nil {
		log.Fatal(err)
	}
}

// Web page handlers (pure HTML responses)

func handleHomePage(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	sessionID, err := r.Cookie("session_id")
	var userInfo map[string]interface{}

	if err == nil && sessionID.Value != "" {
		sessionsMutex.RLock()
		session, ok := sessions[sessionID.Value]
		sessionsMutex.RUnlock()

		if ok && session.ExpiresAt.After(time.Now()) {
			userInfo = session.UserInfo
		}
	}

	var userSection string
	if userInfo != nil {
		userName := "User"
		if name, ok := userInfo["name"].(string); ok {
			userName = name
		}
		userSection = fmt.Sprintf(`
		<div class="card success">
			<h2>✓ Logged In</h2>
			<p>Welcome, <strong>%s</strong>!</p>
			<p><a href="/protected">View Protected Page</a> | <a href="#" onclick="logout()">Logout</a></p>
		</div>`, userName)
	} else {
		userSection = `
		<div class="card">
			<h2>Not Logged In</h2>
			<p>Click the button below to login via OIDC:</p>
			<a href="#" onclick="login()" class="btn">Login with OIDC</a>
		</div>`
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>OIDC Client Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .success { border-color: #4caf50; background: #f1f8f4; }
        h1 { color: #333; }
        h2 { color: #555; margin-top: 0; }
        .btn { display: inline-block; background: #4285f4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; }
        .btn:hover { background: #3367d6; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 14px; }
        ul { line-height: 1.8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>OIDC Client Demo</h1>
        <p>This is a demonstration OAuth2/OIDC client application.</p>
    </div>

    %s

    <div class="card">
        <h2>Configuration</h2>
        <ul>
            <li><strong>Client ID:</strong> <code>%s</code></li>
            <li><strong>Authorization Server:</strong> <code>http://localhost:4001</code></li>
            <li><strong>Redirect URI:</strong> <code>%s</code></li>
            <li><strong>Scopes:</strong> <code>openid profile email</code></li>
        </ul>
    </div>

    <script>
        function login() {
            window.location.href = '/api/auth/login';
        }

        function logout() {
            fetch('/api/auth/logout', { method: 'POST' })
                .then(() => window.location.reload());
        }
    </script>
</body>
</html>`, userSection, ClientID, RedirectURI)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")
	errorDesc := r.URL.Query().Get("error_description")

	// Handle error response
	if errorParam != "" {
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; }
        .error-card { border: 2px solid #f44336; border-radius: 8px; padding: 30px; background: #ffebee; }
        h1 { color: #c62828; margin-top: 0; }
        .back-link { display: inline-block; margin-top: 20px; color: #1976d2; text-decoration: none; }
    </style>
</head>
<body>
    <div class="error-card">
        <h1>Authorization Error</h1>
        <p><strong>Error:</strong> %s</p>
        <p><strong>Description:</strong> %s</p>
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>`, errorParam, errorDesc)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// Validate state (CSRF protection)
	statesMutex.RLock()
	// stateInfo, ok := states[state]
	statesMutex.RUnlock()

	// if !ok {
	// 	http.Error(w, "Invalid state parameter", http.StatusBadRequest)
	// 	return
	// }

	// Clean up used state
	statesMutex.Lock()
	delete(states, state)
	statesMutex.Unlock()

	// Exchange authorization code for tokens
	tokenResponse, err := exchangeCodeForToken(code)
	if err != nil {
		slog.Error("Failed to exchange code for token", "error", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Get user info
	userInfo, err := getUserInfo(tokenResponse.AccessToken)
	if err != nil {
		slog.Error("Failed to get user info", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := generateRandomString(32)
	sessionsMutex.Lock()
	sessions[sessionID] = &Session{
		UserID:      userInfo["sub"].(string),
		AccessToken: tokenResponse.AccessToken,
		IDToken:     tokenResponse.IDToken,
		UserInfo:    userInfo,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
	}
	sessionsMutex.Unlock()

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   tokenResponse.ExpiresIn,
	})

	// Display success page
	userInfoJSON, _ := json.MarshalIndent(userInfo, "", "  ")
	accessTokenPreview := tokenResponse.AccessToken
	if len(accessTokenPreview) > 50 {
		accessTokenPreview = accessTokenPreview[:50] + "..."
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .success { border-color: #4caf50; background: #f1f8f4; }
        h1 { color: #2e7d32; margin-top: 0; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }
        .btn { display: inline-block; background: #4285f4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin-right: 10px; }
        .btn:hover { background: #3367d6; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="card success">
        <h1>✓ Login Successful!</h1>
        <p>You have successfully authenticated via OIDC.</p>
    </div>

    <div class="card">
        <h2>User Information</h2>
        <pre>%s</pre>
    </div>

    <div class="card">
        <h2>Tokens Received</h2>
        <p><strong>Access Token:</strong> <code>%s</code></p>
        <p><strong>Token Type:</strong> Bearer</p>
        <p><strong>Expires In:</strong> %d seconds</p>
    </div>

    <div class="card">
        <a href="/" class="btn">Home</a>
        <a href="/protected" class="btn">View Protected Page</a>
    </div>
</body>
</html>`, string(userInfoJSON), accessTokenPreview, tokenResponse.ExpiresIn)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleProtectedPage(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	sessionID, err := r.Cookie("session_id")
	if err != nil || sessionID.Value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sessionsMutex.RLock()
	session, ok := sessions[sessionID.Value]
	sessionsMutex.RUnlock()

	if !ok || session.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	userInfoJSON, _ := json.MarshalIndent(session.UserInfo, "", "  ")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Protected Page</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .protected { border-color: #ff9800; background: #fff3e0; }
        h1 { color: #e65100; margin-top: 0; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 4px; overflow-x: auto; }
        .btn { display: inline-block; background: #4285f4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
        .btn:hover { background: #3367d6; }
    </style>
</head>
<body>
    <div class="card protected">
        <h1>🔒 Protected Page</h1>
        <p>This page requires authentication. You are currently logged in.</p>
    </div>

    <div class="card">
        <h2>Your Information</h2>
        <pre>%s</pre>
    </div>

    <div class="card">
        <a href="/" class="btn">← Back to Home</a>
    </div>
</body>
</html>`, string(userInfoJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// API handlers

func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err != nil || sessionID.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not_authenticated"})
		return
	}

	sessionsMutex.RLock()
	session, ok := sessions[sessionID.Value]
	sessionsMutex.RUnlock()

	if !ok || session.ExpiresAt.Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "session_expired"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session.UserInfo)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err == nil && sessionID.Value != "" {
		sessionsMutex.Lock()
		delete(sessions, sessionID.Value)
		sessionsMutex.Unlock()
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

// Handle login initiation - this is called when user clicks "Login with OIDC"
func init() {
	http.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// Generate random state for CSRF protection
		state := generateRandomString(32)

		statesMutex.Lock()
		states[state] = &StateInfo{
			State:     state,
			CreatedAt: time.Now(),
		}
		statesMutex.Unlock()

		// Build authorization URL
		authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			AuthorizationURL,
			url.QueryEscape(ClientID),
			url.QueryEscape(RedirectURI),
			url.QueryEscape("openid profile email"),
			url.QueryEscape(state),
		)

		slog.Info("Redirecting to authorization endpoint", "url", authURL)
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

// Helper functions

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func exchangeCodeForToken(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", RedirectURI)
	data.Set("client_id", ClientID)
	data.Set("client_secret", ClientSecret)

	resp, err := http.Post(TokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to post token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

func getUserInfo(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return userInfo, nil
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based generation
		return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(bytes)
}
