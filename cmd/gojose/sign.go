package main

import (
	"flag"
	"fmt"
	"os"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gojose sign:\n")
		fmt.Fprintf(os.Stderr, "  Payload is read from stdin.\n\n")
		fs.PrintDefaults()
	}
	keyPath := fs.String("key", "", "Path to JWK file (required)")
	alg := fs.String("alg", "", "Algorithm in header (e.g. ES256, RS256, HS256) (required)")
	kid := fs.String("kid", "", "Key ID in header (optional)")
	typ := fs.String("typ", "JWS", "Header typ (optional)")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		os.Exit(0)
	}
	_ = fs.Parse(args)

	if *keyPath == "" || *alg == "" {
		fmt.Fprintln(os.Stderr, " -key and -alg are required")
		os.Exit(1)
	}

	keys, err := loadKeysFromSource(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no keys found")
		os.Exit(1)
	}
	jwk := keys[0]

	payload, err := readStdin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}

	algorithm, err := jwk.Algorithm(*alg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "algorithm: %v\n", err)
		os.Exit(1)
	}

	// Set kid on HMAC if provided
	if h, ok := algorithm.(*jose.HMAC); ok && *kid != "" {
		h.Kid = *kid
	}
	if r, ok := algorithm.(*jose.RSA); ok && *kid != "" {
		r.Kid = *kid
	}
	if e, ok := algorithm.(*jose.ECDSA); ok && *kid != "" {
		e.Kid = *kid
	}

	jws := &jose.JWS{
		Payload: base64url.Encode(payload),
	}
	if err := jws.SignWithType(*typ, algorithm); err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}

	compact, err := jws.Compact()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compact: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(compact)
}
