package main

import (
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kanywst/jwtty/pkg/jwtty"
)

func main() {
	var err error

	// dummy claims
	claims := jwt.MapClaims{
		"username": "dummy",
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	// Create JWT with RSA
	log.Println("Create JWT signed with RSA...")
	jwt, err := jwtty.SignWithRSA(claims, "private.rsa.pem")
	if err != nil {
		log.Println(err)
	}
	log.Println("Created JWT signed with RSA:", jwt)

	// Create JWT with EC
	log.Println("Create JWT signed with EC...")
	jwtEC, err := jwtty.SignWithECDSA(claims, "private.ec.pem")
	if err != nil {
		log.Println(err)
	}
	log.Println("Created JWT signed with EC:", jwtEC)

	// Verify JWT with RSA public key.
	log.Println("Verify JWT signed with RSA...")
	err = jwtty.Verify(jwt, "public.rsa.pem")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}

	// Verify JWT with EC public key.
	log.Println("Verify JWT signed with EC...")
	err = jwtty.Verify(jwtEC, "public.ec.pem")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}

	// Run JWK Server with RSA
	var wg sync.WaitGroup
	wg.Add(1)
	go jwtty.JWKServer(":8080", "/jwk", "./public.rsa.pem", &wg)
	wg.Wait()

	// Verify JWT with RSA on the JWK server
	log.Println("Verify JWT with RSA on the JWK server")
	err = jwtty.VerifyFromJWKServer(jwt, "http://localhost:8080/jwk")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}

	// Run JWK Server with EC
	wg.Add(1)
	go jwtty.JWKServer(":8081", "/jwk2", "./public.ec.pem", &wg)
	wg.Wait()

	// Verify JWT with EC on the JWK server
	log.Println("Verify JWT with EC on the JWK server")
	err = jwtty.VerifyFromJWKServer(jwtEC, "http://localhost:8081/jwk2")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}
	time.Sleep(time.Hour)
}
