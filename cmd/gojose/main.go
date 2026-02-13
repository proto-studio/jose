package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, `gojose - JOSE/JWT CLI

Usage:
  gojose <command> [arguments]

Commands and arguments:

  keys create
    -alg string
          Algorithm: HS256, RS256, ES256 (default "ES256")
    -format string
          Output format: jwk or pem (default "jwk")
    -kid string
          Key ID (optional)

  sign
    -key string
          Path to JWK file (required)
    -alg string
          Algorithm in header, e.g. ES256, RS256, HS256 (required)
    -kid string
          Key ID in header (optional)
    -typ string
          Header typ (default "JWS")
    Payload is read from stdin.

  verify-jws
    -key string
          Path to JWK/JWKS file or JWKS URL (required)
    -token string
          Compact JWS (optional; otherwise read from stdin)

  verify-jwt
    -key string
          Path to JWK/JWKS file or JWKS URL (required)
    -token string
          Compact JWT (optional; otherwise read from stdin)

Key source for -key (verify commands):
  - Path to a file containing a single JWK (JSON object)
  - Path to a file containing a JWKS (JSON object with "keys" array)
  - URL to a JWKS endpoint (e.g. https://example.com/.well-known/jwks.json)

Examples:
  gojose keys create -alg ES256 -format jwk
  echo -n '{"sub":"user123"}' | gojose sign -key key.json -alg ES256 -kid mykey
  gojose verify-jwt -key jwks.json < token.jwt

Use "gojose <command> -h" to see flags for a command.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage()
		os.Exit(0)
	}
	args := os.Args[2:]

	switch cmd {
	case "keys":
		if len(args) < 1 || args[0] != "create" {
			fmt.Fprintln(os.Stderr, "expected: gojose keys create [options]")
			os.Exit(1)
		}
		runKeysCreate(args[1:])
	case "sign":
		runSign(args)
	case "verify-jws":
		runVerifyJWS(args)
	case "verify-jwt":
		runVerifyJWT(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}
