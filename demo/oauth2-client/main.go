package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/tendant/simple-idm/pkg/pkce"
	"golang.org/x/oauth2"
)

const (
	// OAuth2 configuration
	clientID     = "golang_app"
	clientSecret = "secret_2ceb79c2e01586cbc94df03a26c0a687807a34e130b3396a2961b73d18178c9a"
	redirectURL  = "http://localhost:8182/demo/callback"

	// OIDC Provider URLs (simple-idm server)
	authURL  = "http://localhost:4000/api/idm/oauth2/authorize"
	tokenURL = "http://localhost:4000/api/idm/oauth2/token"

	// Demo server port
	serverPort = ":8182"
)

var (
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	// In-memory session store (for demo purposes only)
	sessions = make(map[string]*SessionData)
)

type SessionData struct {
	State           string
	CodeVerifier    string
	CodeChallenge   string
	ChallengeMethod string
	UsePKCE         bool
	Token           *oauth2.Token
	IDToken         string
	UserInfo        map[string]interface{}
}

// IDTokenResponse represents the response from the token endpoint with ID token
type IDTokenResponse struct {
	IDToken   string `json:"id_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	Scope     string `json:"scope,omitempty"`
}

func main() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Routes
	r.Get("/", handleHome)
	r.Get("/demo/login", handleLogin)
	r.Get("/demo/callback", handleCallback)
	r.Get("/demo/profile", handleProfile)
	r.Get("/demo/logout", handleLogout)

	fmt.Printf("OAuth2 Demo Client starting on %s\n", serverPort)
	fmt.Printf("Visit http://localhost%s to start the demo\n", serverPort)

	log.Fatal(http.ListenAndServe(serverPort, r))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	session := sessions[sessionID]

	html := `
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Demo Client</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .button { 
            display: inline-block; 
            padding: 10px 20px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 10px 0;
        }
        .button:hover { background: #0056b3; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth2 / OIDC Demo Client</h1>
        <p>This demo shows the OAuth2 Authorization Code flow with simple-idm as the identity provider.</p>
        
        <div class="info">
            <h3>Configuration:</h3>
            <ul>
                <li><strong>Client ID:</strong> ` + clientID + `</li>
                <li><strong>Redirect URI:</strong> ` + redirectURL + `</li>
                <li><strong>Scopes:</strong> openid, profile, email</li>
                <li><strong>Authorization URL:</strong> ` + authURL + `</li>
            </ul>
        </div>`

	if session != nil && session.Token != nil {
		html += `
        <div class="info success">
            <h3>Authenticated!</h3>
            <p>You are successfully logged in.</p>
            <a href="/demo/profile" class="button">View Profile</a>
            <a href="/demo/logout" class="button">Logout</a>
        </div>`
	} else {
		html += `
        <div class="info">
            <h3>Not authenticated</h3>
            <p>Choose your OAuth2 flow:</p>
            <a href="/demo/login" class="button">Login with PKCE (Recommended)</a>
            <a href="/demo/login?pkce=false" class="button">Login without PKCE</a>
        </div>`
	}

	html += `
        <div class="info">
            <h3>Flow Steps:</h3>
            <ol>
                <li>Click "Login with simple-idm"</li>
                <li>You'll be redirected to simple-idm's authorization endpoint</li>
                <li>If not logged in, you'll see the login page</li>
                <li>After login, you'll be redirected back here with an authorization code</li>
                <li>The demo will exchange the code for tokens</li>
                <li>You can then view your profile information</li>
            </ol>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	sessionID := getOrCreateSessionID(w, r)

	// Generate state parameter for CSRF protection
	state := generateRandomString(32)

	// Check if PKCE should be used (default to true for security)
	usePKCE := r.URL.Query().Get("pkce") != "false" // Use PKCE unless explicitly disabled

	sessionData := &SessionData{
		State:   state,
		UsePKCE: usePKCE,
	}

	var authURL string
	if usePKCE {
		// Generate PKCE parameters
		codeVerifier, err := pkce.GenerateCodeVerifier()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate PKCE code verifier: %v", err), http.StatusInternalServerError)
			return
		}

		codeChallenge, err := codeVerifier.GenerateCodeChallenge(pkce.ChallengeS256)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate PKCE code challenge: %v", err), http.StatusInternalServerError)
			return
		}

		// Store PKCE parameters in session
		sessionData.CodeVerifier = codeVerifier.Value
		sessionData.CodeChallenge = codeChallenge.Value
		sessionData.ChallengeMethod = string(codeChallenge.Method)

		// Build authorization URL with PKCE parameters
		authURL = oauth2Config.AuthCodeURL(state,
			oauth2.AccessTypeOffline,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge.Value),
			oauth2.SetAuthURLParam("code_challenge_method", string(codeChallenge.Method)),
		)

		fmt.Printf("Using PKCE flow - Code Challenge: %s, Method: %s\n", codeChallenge.Value, codeChallenge.Method)
	} else {
		// Standard OAuth2 flow without PKCE
		authURL = oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		fmt.Printf("Using standard OAuth2 flow (no PKCE)\n")
	}

	// Store session data
	sessions[sessionID] = sessionData

	fmt.Printf("Redirecting to authorization URL: %s\n", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	session := sessions[sessionID]

	if session == nil {
		http.Error(w, "No session found", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	state := r.URL.Query().Get("state")
	if state != session.State {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		errorMsg := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Authorization failed: %s - %s", errorMsg, errorDesc), http.StatusBadRequest)
		return
	}

	fmt.Printf("Received authorization code: %s\n", code)

	// Exchange code for ID token using custom function
	ctx := context.Background()
	var codeVerifier string
	if session.UsePKCE && session.CodeVerifier != "" {
		codeVerifier = session.CodeVerifier
		fmt.Printf("Using PKCE token exchange with code verifier\n")
	} else {
		fmt.Printf("Using standard token exchange\n")
	}

	idTokenResp, err := exchangeCodeForIDToken(ctx, code, codeVerifier)
	if err != nil {
		fmt.Printf("Token exchange failed: %v\n", err)
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Token exchange successful. ID token: %s...\n", idTokenResp.IDToken[:50])

	// Create a compatible oauth2.Token structure for display purposes
	// Note: We're storing the ID token in the AccessToken field for compatibility with existing UI
	token := &oauth2.Token{
		AccessToken: idTokenResp.IDToken,
		TokenType:   idTokenResp.TokenType,
		Expiry:      time.Now().Add(time.Duration(idTokenResp.ExpiresIn) * time.Second),
	}

	// Store both the oauth2.Token (for compatibility) and the ID token separately
	session.Token = token
	session.IDToken = idTokenResp.IDToken

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	session := sessions[sessionID]

	if session == nil || session.Token == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Profile - OAuth2 Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .button { 
            display: inline-block; 
            padding: 10px 20px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 10px 0;
        }
        .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Profile Information</h1>
        
        <div class="info success">
            <h3>Token Information</h3>
            <p><strong>ID Token:</strong> ` + session.IDToken[:100] + `...</p>
            <p><strong>Token Type:</strong> ` + session.Token.TokenType + `</p>
            <p><strong>Expires:</strong> ` + session.Token.Expiry.Format(time.RFC3339) + `</p>
            <p><em>Note: This is an OIDC ID Token, not an OAuth2 Access Token</em></p>
        </div>`

	// Add PKCE information if available
	if session.UsePKCE {
		html += `
        <div class="info">
            <h3>PKCE Information</h3>
            <p><strong>Used PKCE:</strong> Yes</p>
            <p><strong>Challenge Method:</strong> ` + session.ChallengeMethod + `</p>
            <p><strong>Code Challenge:</strong> ` + session.CodeChallenge + `</p>
            <p><strong>Code Verifier:</strong> ` + session.CodeVerifier + `</p>
        </div>`
	} else {
		html += `
        <div class="info">
            <h3>PKCE Information</h3>
            <p><strong>Used PKCE:</strong> No</p>
        </div>`
	}

	html += `
        
        <div class="info">
            <h3>Raw Token Response</h3>
            <pre>` + fmt.Sprintf("%+v", session.Token) + `</pre>
        </div>
        
        <a href="/" class="button">Back to Home</a>
        <a href="/demo/logout" class="button">Logout</a>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	delete(sessions, sessionID)

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func getOrCreateSessionID(w http.ResponseWriter, r *http.Request) string {
	sessionID := getSessionID(r)
	if sessionID == "" {
		sessionID = generateRandomString(32)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600, // 1 hour
		})
	}
	return sessionID
}

// exchangeCodeForIDToken performs a custom token exchange that handles ID token response
func exchangeCodeForIDToken(ctx context.Context, code, codeVerifier string) (*IDTokenResponse, error) {
	// Prepare form data for token exchange
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURL)

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var tokenResp IDTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
