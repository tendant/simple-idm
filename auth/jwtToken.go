package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/token"
)

// Jwt implements the token.TokenService interface
type Jwt struct {
	Secret          string
	CoookieHttpOnly bool
	CookieSecure    bool
}

type Option func(*Jwt)

func WithCookieHttpOnly(httpOnly bool) Option {
	return func(jwt *Jwt) {
		jwt.CoookieHttpOnly = httpOnly
	}
}

func WithCookieSecure(secure bool) Option {
	return func(jwt *Jwt) {
		jwt.CookieSecure = secure
	}
}

func NewJwtServiceOptions(secret string, opts ...Option) *Jwt {
	jwtSvc := &Jwt{Secret: secret}

	for _, opt := range opts {
		opt(jwtSvc)
	}

	return jwtSvc
}

func (j Jwt) CreateTokenStr(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signingKey := []byte(j.Secret)
	ss, err := signedString(signingKey, token)
	if err != nil {
		slog.Error("Failed sign JWT Claim string!", "err", err)
		return "", err
	}
	return ss, nil
}

// SignedString creates and returns a complete, signed JWT.
// The token is signed using the SigningMethod specified in the token.
func signedString(key interface{}, t *jwt.Token) (string, error) {
	var sstr string
	var sig []byte
	var err error
	if sstr, err = signingString(t); err != nil {
		return "", err
	}
	sig, err = t.Method.Sign(sstr, key)
	if err != nil {
		return "", err
	}
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join([]string{sstr, encodedSig}, "."), nil
}

// SigningString generates the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func signingString(t *jwt.Token) (string, error) {
	var err error
	var jsonValue []byte

	if jsonValue, err = json.Marshal(t.Header); err != nil {
		return "", err
	}
	header := encodeSegment(jsonValue)

	if jsonValue, err = json.Marshal(t.Claims); err != nil {
		return "", err
	}
	claim := encodeSegment(jsonValue)

	return strings.Join([]string{header, claim}, "."), nil
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

// Claims struct for JWT claims
type Claims struct {
	CustomClaims interface{} `json:"custom_claims,inline"`
	jwt.RegisteredClaims
}

// CreateToken implements token.TokenService
func (j Jwt) CreateToken(user string) (token.Token, error) {
	accessToken, err := j.CreateAccessToken(user)
	if err != nil {
		slog.Error("Failed create access token!", "err", err)
		return token.Token{}, err
	}
	refreshToken, err := j.CreateRefreshToken(user)
	if err != nil {
		slog.Error("Failed create refresh token!", "err", err)
		return token.Token{}, err
	}
	return token.Token{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
	}, nil
}

// Ensure Jwt implements token.TokenService
var _ token.TokenService = (*Jwt)(nil)

func (j Jwt) ParseTokenStr(tokenStr string) (*jwt.Token, error) {
	signingKey := []byte(j.Secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		slog.Error("Failed parse JWT string!", "err", err)
		return token, err
	}
	claims := token.Claims.(jwt.MapClaims)
	customClaims := new(Claims)
	err = LoadFromMap(customClaims, claims)
	if err == nil && token.Valid {
		return token, nil
	}
	slog.Error("Failed parse token claims!", "err", err)
	return token, errors.New("failed_parse_token_claims")
}

func LoadFromMap[T any](c *T, m map[string]interface{}) error {
	data, err := json.Marshal(m)
	if err == nil {
		err = json.Unmarshal(data, c)
	}
	return err
}

// CreateAccessToken implements token.TokenService
func (j Jwt) CreateAccessToken(claimData interface{}) (token.IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	accessToken, err := j.CreateTokenStr(claims)
	return token.IdmToken{Token: accessToken, Expiry: claims.ExpiresAt.Time}, err
}

// CreateRefreshToken implements token.TokenService
func (j Jwt) CreateRefreshToken(claimData interface{}) (token.IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	refreshToken, err := j.CreateTokenStr(claims)
	return token.IdmToken{Token: refreshToken, Expiry: claims.ExpiresAt.Time}, err
}

// CreatePasswordResetToken implements token.TokenService
func (j Jwt) CreatePasswordResetToken(claimData interface{}) (string, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	pwdResetToken, err := j.CreateTokenStr(claims)
	return pwdResetToken, err
}

// CreateLogoutToken implements token.TokenService
func (j Jwt) CreateLogoutToken(claimData interface{}) (token.IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	accessToken, err := j.CreateTokenStr(claims)
	return token.IdmToken{Token: accessToken, Expiry: claims.ExpiresAt.Time}, err
}

// CreateTempToken implements token.TokenService
func (j Jwt) CreateTempToken(claimData interface{}) (token.IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// Short expiry for 2FA verification
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"2fa"},
		},
	}
	tempToken, err := j.CreateTokenStr(claims)
	return token.IdmToken{Token: tempToken, Expiry: claims.ExpiresAt.Time}, err
}

func (j Jwt) ValidateRefreshToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := j.ParseTokenStr(tokenString)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Validate the token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token has expired")
			}
		} else {
			return nil, fmt.Errorf("invalid expiration claim")
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
