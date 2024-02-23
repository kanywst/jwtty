# create key

- [create key](#create-key)
  - [RSA](#rsa)
  - [EC](#ec)

## RSA

```bash
openssl genrsa -out private.key.rsa.pem 4096
openssl rsa -in key.pem -pubout -out public.key.rsa.pem
```

```bash
openssl genrsa -out private.key.rsa.dummy.pem 4096
openssl rsa -in private.key.rsa.dummy.pem -pubout -out public.key.rsa.dummy.pem
```

## EC

```bash
openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout -out pubkey.pem
```
