package tokengenerator

import (
	"net/http"
	"time"
)

// CookieSetter interface defines methods for cookie operations
type CookieSetter interface {
	// SetCookie sets a cookie with the given value and expiry
	SetCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) error

	// ClearCookie clears a cookie
	ClearCookie(w http.ResponseWriter, tokenName string) error
}

// BaseCookieSetter provides a base implementation of CookieSetter
type BaseCookieSetter struct {
	Path     string
	HttpOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   int
}

// SetCookie sets a cookie with the given value and expiry
func (c *BaseCookieSetter) SetCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) error {
	cookie := &http.Cookie{
		Name:     tokenName,
		Path:     c.Path,
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: c.HttpOnly,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

// ClearCookie clears a cookie
func (c *BaseCookieSetter) ClearCookie(w http.ResponseWriter, tokenName string) error {
	cookie := &http.Cookie{
		Name:     tokenName,
		Path:     c.Path,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: c.HttpOnly,
		Secure:   c.Secure,
	}

	http.SetCookie(w, cookie)
	return nil
}

// NewCookieSetter creates a new cookie setter
func NewCookieSetter(httpOnly, secure bool) CookieSetter {
	return &BaseCookieSetter{
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
