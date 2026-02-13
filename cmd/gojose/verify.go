package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func runVerifyJWS(args []string) {
	fs := flag.NewFlagSet("verify-jws", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gojose verify-jws:\n")
		fmt.Fprintf(os.Stderr, "  Token is read from stdin if -token is not set.\n\n")
		fs.PrintDefaults()
	}
	keySource := fs.String("key", "", "Path to JWK/JWKS file or JWKS URL (required)")
	tokenArg := fs.String("token", "", "Compact JWS (optional; otherwise read from stdin)")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		os.Exit(0)
	}
	_ = fs.Parse(args)

	if *keySource == "" {
		fmt.Fprintln(os.Stderr, "-key is required")
		os.Exit(1)
	}

	var compact string
	if *tokenArg != "" {
		compact = *tokenArg
	} else {
		payload, err := readStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		compact = string(trimStdin(payload))
	}

	jws, err := jose.ParseCompactJWS(compact)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse JWS: %v\n", err)
		os.Exit(1)
	}

	keys, err := loadKeysFromSource(*keySource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no keys found")
		os.Exit(1)
	}

	if !verifyWithKeys(jws, keys) {
		fmt.Fprintln(os.Stderr, "verification failed")
		os.Exit(1)
	}

	// Output decoded payload to stdout
	decoded, err := base64url.Decode(jws.Payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode payload: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(decoded)
	if len(decoded) > 0 && decoded[len(decoded)-1] != '\n' {
		os.Stdout.WriteString("\n")
	}
}

func runVerifyJWT(args []string) {
	fs := flag.NewFlagSet("verify-jwt", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gojose verify-jwt:\n")
		fmt.Fprintf(os.Stderr, "  Token is read from stdin if -token is not set.\n\n")
		fs.PrintDefaults()
	}
	keySource := fs.String("key", "", "Path to JWK/JWKS file or JWKS URL (required)")
	tokenArg := fs.String("token", "", "Compact JWT (optional; otherwise read from stdin)")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		os.Exit(0)
	}
	_ = fs.Parse(args)

	if *keySource == "" {
		fmt.Fprintln(os.Stderr, "-key is required")
		os.Exit(1)
	}

	var compact string
	if *tokenArg != "" {
		compact = *tokenArg
	} else {
		payload, err := readStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		compact = string(trimStdin(payload))
	}

	jws, err := jose.ParseCompactJWS(compact)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse JWT: %v\n", err)
		os.Exit(1)
	}

	keys, err := loadKeysFromSource(*keySource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no keys found")
		os.Exit(1)
	}

	if !verifyWithKeys(jws, keys) {
		fmt.Fprintln(os.Stderr, "verification failed")
		os.Exit(1)
	}

	jwt, err := jose.JWTFromJWS(jws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JWT payload: %v\n", err)
		os.Exit(1)
	}

	// Output claims as JSON
	out, err := json.MarshalIndent(jwt.Claims, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal claims: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
