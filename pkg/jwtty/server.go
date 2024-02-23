package jwtty

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

// JWK struct represents a JSON Web Key
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

func JWKServer(addr, endpoint, publicPath string, wg *sync.WaitGroup) {
	defer wg.Done()
	http.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		jwkHandler(w, r, publicPath)
	})
	log.Println("JWK Server starting...")
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("JWK Server failed to start: %v", err)
		}
	}()
}

func jwkHandler(w http.ResponseWriter, r *http.Request, p string) {
	publicKeyBytes, err := ioutil.ReadFile(p)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read public key file: %v", err), http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		http.Error(w, "Failed to decode PEM block containing public key", http.StatusInternalServerError)
		return
	}

	var pub interface{}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "EC PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	default:
		http.Error(w, "Unsupported public key type", http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse public key: %v", err), http.StatusInternalServerError)
		return
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		jwk := JWK{
			Kty: "EC",
			Alg: "ES256",
			Use: "sig",
			Crv: getCurveName(pub.Curve),
			X:   encodeToBase64URL(pub.X.Bytes()),
			Y:   encodeToBase64URL(pub.Y.Bytes()),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwk)
	case *rsa.PublicKey:
		jwk := JWK{
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			N:   encodeToBase64URL(pub.N.Bytes()),
			E:   encodeToBase64URL(bigEndianBytes(int(pub.E))),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwk)
	default:
		http.Error(w, "Unsupported public key type", http.StatusInternalServerError)
	}
}

func encodeToBase64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func bigEndianBytes(n int) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(n))
	return bytes
}

func getCurveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
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
