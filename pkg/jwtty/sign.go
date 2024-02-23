package jwtty

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/golang-jwt/jwt/v5"
)

func Sign(c jwt.MapClaims, p string) (string, error) {
	privateKeyBytes, err := ioutil.ReadFile(p)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	var privateKey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		privateKey = key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		privateKey = key
	default:
		return "", errors.New("unsupported private key type")
	}

	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
