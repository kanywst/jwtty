package main

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kanywst/jwtty/pkg/jwtty"
)

func main() {
	var err error

	// dummy claims
	claims := jwt.MapClaims{
		"username": "dummy",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 有効期限を1日後に設定
	}

	// RSA
	log.Println("Create JWT signed with RSA...")
	jwt, err := jwtty.Sign(claims, "private.key.rsa.pem")
	if err != nil {
		log.Println(err)
	}
	log.Println("Created JWT signed with RSA:", jwt)
	log.Println("Verify JWT signed with RSA...")
	err = jwtty.Verify(jwt, "public.key.rsa.pem")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}

	fmt.Println("=====================================================")
	// EC
	log.Println("Create JWT signed with EC...")
	jwtEC, err := jwtty.Sign(claims, "private.key.ec.pem")
	if err != nil {
		log.Println(err)
	}
	log.Println("Created JWT signed with EC:", jwtEC)
	log.Println("Verify JWT signed with EC...")
	err = jwtty.Verify(jwtEC, "public.key.ec.pem")
	if err != nil {
		log.Println("err:", err)
	} else {
		log.Println("JWT is valid")
	}
}
