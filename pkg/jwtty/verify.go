package jwtty

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func Verify(tokenString, p string) error {
	publicKeyBytes, err := ioutil.ReadFile(p)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %v", err)
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %v", err)
	}

	if !token.Valid {
		// TODO: CHECK DETAILS
		return errors.New("JWT is invalid")
	}

	return nil
}

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

	var key interface{}
	switch jwk.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return fmt.Errorf("failed to decode modulus: %v", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return fmt.Errorf("failed to decode exponent: %v", err)
		}
		key = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
	case "EC":
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return fmt.Errorf("failed to decode ECDSA X coordinate: %v", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return fmt.Errorf("failed to decode ECDSA Y coordinate: %v", err)
		}
		curve := getCurveByName(jwk.Crv)
		if curve == nil {
			return fmt.Errorf("unsupported ECDSA curve: %v", jwk.Crv)
		}
		key = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	default:
		return fmt.Errorf("unsupported key type: %v", jwk.Kty)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch key := key.(type) {
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
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
