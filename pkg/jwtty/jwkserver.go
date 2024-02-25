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
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

func JWKServer(addr, endpoint, publicPath string, wg *sync.WaitGroup) {
	defer wg.Done()
	http.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		jwkHandler(w, r, publicPath)
	})

	log.Printf("JWK Server starting on %s%s\n", addr, endpoint)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("JWK Server failed to start: %v", err)
	}
}

func jwkHandler(w http.ResponseWriter, r *http.Request, p string) {
	file, err := os.Open(p)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open public key file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file info: %v", err), http.StatusInternalServerError)
		return
	}

	publicKeyBytes := make([]byte, fileInfo.Size())
	_, err = file.Read(publicKeyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read public key file: %v", err), http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		http.Error(w, "Failed to decode PEM block containing public key", http.StatusInternalServerError)
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
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
		writeJSONResponse(w, jwk)
	case *rsa.PublicKey:
		jwk := JWK{
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			N:   encodeToBase64URL(pub.N.Bytes()),
			E:   encodeToBase64URL(bigEndianBytes(int(pub.E))),
		}
		writeJSONResponse(w, jwk)
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

func writeJSONResponse(w http.ResponseWriter, jwk JWK) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwk); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode JSON: %v", err), http.StatusInternalServerError)
	}
}
