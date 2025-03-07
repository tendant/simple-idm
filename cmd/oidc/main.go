package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/tendant/simple-idm/pkg/oidc"
)

// Simple HTML template for the callback page
const callbackTmpl = `
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Callback</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .success { color: green; }
        .error { color: red; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth2 Callback</h1>
        
        {{if .Error}}
            <div class="card error">
                <h2>Error</h2>
                <p>{{.Error}}</p>
                <p>{{.ErrorDescription}}</p>
            </div>
        {{else}}
            <div class="card success">
                <h2>Success!</h2>
                <p>Authorization code received successfully.</p>
                <p>Code: <code>{{.Code}}</code></p>
                <p>State: <code>{{.State}}</code></p>
            </div>
            
            <div class="card">
                <h3>Next Steps</h3>
                <p>Use this code to request an access token from the token endpoint:</p>
                <pre>curl -X POST \
    http://localhost:8080/token \
    -d "grant_type=authorization_code" \
    -d "code={{.Code}}" \
    -d "redirect_uri=http://localhost:8080/callback" \
    -d "client_id=myclient"</pre>
            </div>
        {{end}}
    </div>
</body>
</html>
`

// CallbackHandler processes the OAuth2 callback
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Create template data
	data := map[string]string{
		"Code":             code,
		"State":            state,
		"Error":            error,
		"ErrorDescription": errorDescription,
	}

	// Parse and execute template
	tmpl, err := template.New("callback").Parse(callbackTmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Template execution error", http.StatusInternalServerError)
	}

	// Log the callback
	log.Printf("Callback received - Code: %s, State: %s, Error: %s", code, state, error)
}

// Simple home page with a link to start the OAuth2 flow
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Create the authorization URL
	authURL, err := url.Parse("http://localhost:8080/authorize")
	if err != nil {
		http.Error(w, "Error creating auth URL", http.StatusInternalServerError)
		return
	}

	// Add query parameters
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "myclient")
	q.Set("redirect_uri", "http://localhost:8080/callback")
	q.Set("scope", "openid profile email")
	q.Set("state", "random-state-value")
	authURL.RawQuery = q.Encode()

	// HTML content
	htmlContent := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>OIDC Test Client</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 40px; }
			.container { max-width: 800px; margin: 0 auto; }
			.btn { display: inline-block; background: #4285f4; color: white; padding: 10px 20px; 
				   text-decoration: none; border-radius: 5px; font-weight: bold; }
			.btn:hover { background: #3367d6; }
		</style>
	</head>
	<body>
		<div class="container">
			<h1>OIDC Test Client</h1>
			<p>Click the button below to start the OAuth2 authorization flow:</p>
			<a href="%s" class="btn">Login with OIDC</a>
		</div>
	</body>
	</html>
	`, authURL.String())

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlContent)
}

func main() {
	handle := oidc.NewHandle()

	// OIDC endpoints
	http.HandleFunc("/authorize", handle.AuthorizeEndpoint)
	http.HandleFunc("/token", handle.TokenEndpoint)
	http.HandleFunc("/userinfo", handle.UserInfoEndpoint)
	http.HandleFunc("/jwks", handle.JwksEndpoint)

	// Client endpoints
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/callback", callbackHandler)

	log.Println("OIDC Provider running on http://localhost:8080")
	log.Println("Visit http://localhost:8080/ to start the OAuth2 flow")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
