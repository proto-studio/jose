package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func runKeysCreate(args []string) {
	fs := flag.NewFlagSet("keys create", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gojose keys create:\n")
		fs.PrintDefaults()
	}
	alg := fs.String("alg", "ES256", "Algorithm: HS256, RS256, ES256")
	kid := fs.String("kid", "", "Key ID (optional)")
	format := fs.String("format", "jwk", "Output format: jwk or pem")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		os.Exit(0)
	}
	_ = fs.Parse(args)

	var jwk *jose.JWK
	switch *alg {
	case "HS256":
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating secret: %v\n", err)
			os.Exit(1)
		}
		jwk = &jose.JWK{
			Kty: "oct",
			K:   base64url.Encode(secret),
			Alg: "HS256",
			Use: "sig",
			Kid: *kid,
		}
		if *format == "pem" {
			fmt.Fprintln(os.Stderr, "PEM format not supported for symmetric keys; outputting JWK.")
			*format = "jwk"
		}
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating RSA key: %v\n", err)
			os.Exit(1)
		}
		jwk = &jose.JWK{
			Kty: "RSA",
			N:   base64url.Encode(privateKey.N.Bytes()),
			E:   base64url.Encode(big.NewInt(int64(privateKey.E)).Bytes()),
			D:   base64url.Encode(privateKey.D.Bytes()),
			Alg: "RS256",
			Use: "sig",
			Kid: *kid,
		}
		if *format == "pem" {
			writeRSAPEM(privateKey)
			return
		}
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating ECDSA key: %v\n", err)
			os.Exit(1)
		}
		jwk = &jose.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64url.Encode(privateKey.X.Bytes()),
			Y:   base64url.Encode(privateKey.Y.Bytes()),
			D:   base64url.Encode(privateKey.D.Bytes()),
			Alg: "ES256",
			Use: "sig",
			Kid: *kid,
		}
		if *format == "pem" {
			writeECPEM(privateKey)
			return
		}
	default:
		fmt.Fprintf(os.Stderr, "Unsupported algorithm: %s\n", *alg)
		os.Exit(1)
	}

	// JWK output
	out, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JWK: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func writeRSAPEM(privateKey *rsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling RSA key: %v\n", err)
		os.Exit(1)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := pem.Encode(os.Stdout, block); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing PEM: %v\n", err)
		os.Exit(1)
	}
}

func writeECPEM(privateKey *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling EC key: %v\n", err)
		os.Exit(1)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	if err := pem.Encode(os.Stdout, block); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing PEM: %v\n", err)
		os.Exit(1)
	}
}
