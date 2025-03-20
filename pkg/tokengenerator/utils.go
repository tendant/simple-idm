package tokengenerator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateTokenStr(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signingKey := []byte(secret)
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

func ParseTokenStr(secret string, tokenStr string) (*jwt.Token, error) {
	signingKey := []byte(secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		slog.Error("Failed parse JWT string!", "err", err)
		return token, err
	}

	// Since we don't have a LoadFromMap function or Claims struct defined,
	// we'll just return the token if it's valid
	if token.Valid {
		return token, nil
	}

	slog.Error("Failed parse token claims!", "err", "token invalid")
	return token, fmt.Errorf("failed_parse_token_claims")
}

func ValidateRefreshToken(secret string, tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := ParseTokenStr(secret, tokenString)

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
