package jwtty

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyWithKey verifies the JWT using the provided public key.
func VerifyWithKey(tokenString string, publicKey interface{}) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch publicKey := publicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		default:
			return nil, fmt.Errorf("unsupported key type")
		}
	})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %v", err)
	}

	if !token.Valid {
		return errors.New("JWT is invalid")
	}

	return nil
}

// ParsePublicKeyFromPEM parses the public key from PEM format.
func ParsePublicKeyFromPEM(publicKeyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// ParsePublicKeyFromJWK parses the public key from JWK format.
func ParsePublicKeyFromJWK(jwk JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode modulus: %v", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode exponent: %v", err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}, nil
	case "EC":
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ECDSA X coordinate: %v", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ECDSA Y coordinate: %v", err)
		}
		curve := getCurveByName(jwk.Crv)
		if curve == nil {
			return nil, fmt.Errorf("unsupported ECDSA curve: %v", jwk.Crv)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", jwk.Kty)
	}
}

// VerifyFromJWKServer fetches the public key from the specified JWK server and verifies the JWT using it.
func VerifyFromJWKServer(tokenString, jwkServerURL string) error {
	resp, err := http.Get(jwkServerURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWK from server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWK server returned non-200 status code: %v", resp.StatusCode)
	}

	var jwk JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return fmt.Errorf("failed to decode JWK response: %v", err)
	}

	publicKey, err := ParsePublicKeyFromJWK(jwk)
	if err != nil {
		return err
	}

	return VerifyWithKey(tokenString, publicKey)
}

// JWK represents a JSON Web Key (JWK).
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Crv string `json:"crv,omitempty"`
}

func getCurveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
