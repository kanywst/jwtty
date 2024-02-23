package jwtty

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

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
