package token

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"

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
