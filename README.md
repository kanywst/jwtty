# jwtty

- [jwtty](#jwtty)
  - [Overview](#overview)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)

## Overview

This package provides functionalities for creating and verifying JSON Web Tokens (JWT) in Go (Golang). It supports both RSA and ECDSA algorithms for signing and verification of JWTs. Additionally, it offers the ability to run a JSON Web Key (JWK) server for dynamically retrieving public keys used in JWT verification.

## Features

- Create JWTs signed with RSA or ECDSA algorithms.
- Verify JWTs using public keys for RSA or ECDSA.
- Run a JWK server for dynamic retrieval of public keys used in JWT verification.

## Installation

```bash
go get -u github.com/kanywst/jwtty
```

## Usage

```golang
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
        "exp":      time.Now().Add(time.Hour * 24).Unix(), // 有効期限を1日後に設定
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
```

```bash
$ go run main.go
2024/02/23 20:22:28 Create JWT signed with RSA...
2024/02/23 20:22:28 Created JWT signed with RSA: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDg3NzM3NDgsInVzZXJuYW1lIjoiZHVtbXkifQ.${sig}
2024/02/23 20:22:28 Create JWT signed with EC...
2024/02/23 20:22:28 Created JWT signed with EC: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDg3NzM3NDgsInVzZXJuYW1lIjoiZHVtbXkifQ.${sig}
2024/02/23 20:22:28 Verify JWT signed with RSA...
2024/02/23 20:22:28 JWT is valid
2024/02/23 20:22:28 Verify JWT signed with EC...
2024/02/23 20:22:28 JWT is valid
2024/02/23 20:22:28 JWK Server starting...
2024/02/23 20:22:28 Verify JWT with RSA on the JWK server
2024/02/23 20:22:28 JWT is valid
2024/02/23 20:22:28 JWK Server starting...
2024/02/23 20:22:28 Verify JWT with EC on the JWK server
2024/02/23 20:22:28 JWT is valid
```

```bash
$ curl localhost:8080/jwk
{"kty":"RSA","alg":"RS256","use":"sig","n":"${masked}","e":"AAEAAQ"}
```

```bash
$ curl localhost:8081/jwk2
{"kty":"EC","alg":"ES256","use":"sig","x":"${masked}","y":"${masked}","crv":"P-256"}
```
