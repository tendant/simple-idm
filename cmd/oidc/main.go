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
        form { margin-top: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #4285f4; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #3367d6; }
        #token-response { margin-top: 20px; display: none; }
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
                <h3>Exchange Code for Token</h3>
                <p>Use the form below to exchange your code for an access token:</p>
                
                <form id="token-form">
                    <label for="code">Authorization Code:</label>
                    <input type="text" id="code" name="code" value="{{.Code}}" readonly>
                    
                    <label for="redirect_uri">Redirect URI:</label>
                    <input type="text" id="redirect_uri" name="redirect_uri" value="http://localhost:8080/callback">
                    
                    <label for="client_id">Client ID:</label>
                    <input type="text" id="client_id" name="client_id" value="myclient">
                    
                    <label for="client_secret">Client Secret:</label>
                    <input type="text" id="client_secret" name="client_secret" value="mysecret">
                    
                    <button type="submit">Exchange for Token</button>
                </form>
                
                <div id="token-response" class="card">
                    <h3>Token Response</h3>
                    <pre id="token-result"></pre>
                </div>
            </div>
            
            <div class="card">
                <h3>Command Line</h3>
                <p>Or use this curl command to request an access token from the token endpoint:</p>
                <pre>curl -X POST \
    http://localhost:8080/token \
    -d "grant_type=authorization_code" \
    -d "code={{.Code}}" \
    -d "redirect_uri=http://localhost:8080/callback" \
    -d "client_id=myclient" \
    -d "client_secret=mysecret"</pre>
            </div>
            
            <script>
                document.getElementById('token-form').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const code = document.getElementById('code').value;
                    const redirectUri = document.getElementById('redirect_uri').value;
                    const clientId = document.getElementById('client_id').value;
                    const clientSecret = document.getElementById('client_secret').value;
                    
                    const formData = new URLSearchParams();
                    formData.append('grant_type', 'authorization_code');
                    formData.append('code', code);
                    formData.append('redirect_uri', redirectUri);
                    formData.append('client_id', clientId);
                    formData.append('client_secret', clientSecret);
                    
                    try {
                        const response = await fetch('/token', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: formData
                        });
                        
                        const result = await response.json();
                        document.getElementById('token-result').textContent = JSON.stringify(result, null, 2);
                        document.getElementById('token-response').style.display = 'block';
                    } catch (error) {
                        document.getElementById('token-result').textContent = 'Error: ' + error.message;
                        document.getElementById('token-response').style.display = 'block';
                    }
                });
            </script>
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
