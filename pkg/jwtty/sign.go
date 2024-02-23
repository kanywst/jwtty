package jwtty

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func SignWithRSA(c jwt.MapClaims, p string) (string, error) {
	key, err := parsePrivateKey(p)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	signedToken, err := sign(token, key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func SignWithECDSA(c jwt.MapClaims, p string) (string, error) {
	key, err := parsePrivateKey(p)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	signedToken, err := sign(token, key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func sign(token *jwt.Token, key interface{}) (string, error) {
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}

func parsePrivateKey(p string) (interface{}, error) {
	file, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	privateKeyBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	var key interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}
	default:
		return nil, errors.New("unsupported private key type")
	}
	return key, nil
}
