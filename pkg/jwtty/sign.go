package jwtty

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang-jwt/jwt/v5"
)

func SignWithRSA(c jwt.MapClaims, p string) (string, error) {
	privateKeyBytes, err := ioutil.ReadFile(p)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("failed to parse RSA private key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	signedToken, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func SignWithECDSA(c jwt.MapClaims, p string) (string, error) {
	privateKeyBytes, err := ioutil.ReadFile(p)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	var key interface{}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse EC private key: %v", err)
		}
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}
	default:
		return "", errors.New("unsupported private key type")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)

	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}
