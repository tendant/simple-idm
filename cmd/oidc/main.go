package main

import (
	"log"
	"net/http"

	"github.com/tendant/simple-idm/pkg/oidc"
)

func main() {
	handle := oidc.NewHandle()
	http.HandleFunc("/authorize", handle.AuthorizeEndpoint)
	http.HandleFunc("/token", handle.TokenEndpoint)
	http.HandleFunc("/userinfo", handle.UserInfoEndpoint)
	http.HandleFunc("/jwks", handle.JwksEndpoint)

	log.Println("OIDC Provider running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
