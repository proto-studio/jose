package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func main() {
	// Create the jwt command
	jwtCmd := flag.NewFlagSet("jwt", flag.ExitOnError)
	algFlag := jwtCmd.String("alg", "HS256", "Algorithm to use for signing")
	kidFlag := jwtCmd.String("kid", "", "Key ID (optional)")

	if len(os.Args) < 2 {
		fmt.Println("expected 'create' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "create":
		if len(os.Args) < 3 {
			fmt.Println("expected 'jwt' subcommand")
			os.Exit(1)
		}

		switch os.Args[2] {
		case "jwt":
			jwtCmd.Parse(os.Args[3:])
			createJWK(*algFlag, *kidFlag)
		default:
			fmt.Printf("unknown subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	default:
		fmt.Printf("unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func createJWK(alg string, kid string) {
	var jwk *jose.JWK

	switch alg {
	case "HS256":
		// Generate random secret for HMAC
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			fmt.Printf("Error generating secret: %v\n", err)
			os.Exit(1)
		}
		jwk = &jose.JWK{
			Kty: "oct",
			K:   base64url.Encode(secret),
			Alg: "HS256",
			Use: "sig",
			Kid: kid,
		}

	case "RS256":
		// Generate RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("Error generating RSA key: %v\n", err)
			os.Exit(1)
		}
		jwk = &jose.JWK{
			Kty: "RSA",
			N:   base64url.Encode(privateKey.N.Bytes()),
			E:   base64url.Encode(big.NewInt(int64(privateKey.E)).Bytes()),
			D:   base64url.Encode(privateKey.D.Bytes()),
			Alg: "RS256",
			Use: "sig",
			Kid: kid,
		}

	case "ES256":
		// Generate ECDSA key pair using P-256 curve
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Printf("Error generating ECDSA key: %v\n", err)
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
			Kid: kid,
		}

	default:
		fmt.Printf("Unsupported algorithm: %s\n", alg)
		os.Exit(1)
	}

	// Output JWK as JSON
	output, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JWK: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
