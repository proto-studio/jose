# JOSE

[![Tests](https://github.com/proto-studio/jose/actions/workflows/tests.yml/badge.svg)](https://github.com/proto-studio/jose/actions/workflows/tests.yml)
[![GoDoc](https://pkg.go.dev/badge/proto.zip/studio/jose)](https://pkg.go.dev/proto.zip/studio/jose)
[![codecov](https://codecov.io/gh/proto-studio/jose/graph/badge.svg)](https://codecov.io/gh/proto-studio/jose)
[![Discord Chat](https://img.shields.io/badge/Discord-chat-blue?logo=Discord&logoColor=white)](https://proto.studio/social/discord)

> ⚠️ **Warning:** This is prerelease software and has not yet been rigorously tested. Use at your own risk in production environments.

This library is a Go implementation of **JOSE** (JSON Object Signing and Encryption) and **JWT** (JSON Web Token): parsing, signing, verification, JWK/JWKS handling, and validation with declarative rules.

Project goals:

1. **Core JOSE** (`pkg/jose`): JWS compact/serialized form, JWT claims, JWK and JWKS parsing and key selection, multiple algorithms (HMAC, RSA, ECDSA, optional "none").
2. **Validation** (`pkg/josevalidators`): Rule-based validation for JWS, JWT, JWK, and JWKS, with signature verification (single key, JWKS, or JWKS URL with caching), powered by [ProtoValidate](https://github.com/proto-studio/protovalidate) (Go package: `proto.zip/studio/validate`).

Features:

- Parse and produce JWS in compact form; flatten to one signature for verification.
- JWT claim handling with standard claim keys (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`).
- JWK and JWKS: parse, select by `alg`/`kid`, and verify JWS with a key set or a JWKS URL (HTTP caching with ETag/Last-Modified and Cache-Control).
- Validation rule sets for JWS, JWT, JWK, and JWKS with clear, structured errors from `proto.zip/studio/validate`.
- Optional signature verification via `WithVerifyJWK`, `WithJWKS`, or `WithJWKSURL`; `exp`/`nbf` checks; custom claim rules.

## Installation

### Library

```bash
go get proto.zip/studio/jose
```

### gojose CLI

To install the **gojose** command-line tool (create keys, sign JWS, verify JWS/JWT):

```bash
go install proto.zip/studio/jose/cmd/gojose@latest
```

Or build from a clone:

```bash
git clone https://github.com/proto-studio/jose
cd jose
go build -o gojose ./cmd/gojose
./gojose keys create -alg ES256 -format jwk
```

**Commands:**

| Command        | Description |
|----------------|-------------|
| `keys create`  | Create a new key; output as JWK or PEM (`-format jwk` or `-format pem`). Algorithms: `HS256`, `RS256`, `ES256`. |
| `sign`        | Sign a JWS: key from file (`-key`), header `-alg` and optional `-kid`, payload from stdin. |
| `verify-jws`  | Verify a compact JWS; key from a JWK file, JWKS file, or JWKS URL (`-key`); token from stdin or `-token`. Outputs decoded payload. |
| `verify-jwt`  | Verify a JWT (same key sources); token from stdin or `-token`. Outputs claims as JSON. |

**Examples:**

```bash
# Create an ES256 key (JWK)
gojose keys create -alg ES256 -format jwk -kid mykey > key.json

# Create an RSA key (PEM)
gojose keys create -alg RS256 -format pem -kid rsa1 > key.pem

# Sign payload (stdin) with key file
echo -n '{"sub":"user123"}' | gojose sign -key key.json -alg ES256 -kid mykey

# Verify JWT (stdin or -token)
gojose verify-jwt -key key.json < token.jwt
gojose verify-jwt -key https://example.com/.well-known/jwks.json -token "$TOKEN"
```

## Getting Started

### Quick Start

```bash
go get proto.zip/studio/jose
```

Parse and validate a JWT:

```go
package main

import (
	"context"
	"fmt"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/rules"
)

func main() {
	ruleSet := josevalidators.JWT().
		WithClaim("scope", rules.String().Any())

	ctx := context.Background()
	token := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9."
	var jwt *jose.JWT
	if err := ruleSet.Apply(ctx, token, &jwt); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(jwt.Claims["scope"]) // openid
}
```

Use the core package for signing and low-level JWS/JWT handling; use `josevalidators` when you need validation, claim rules, or verification against a JWKS URL.

## Versioning

This package follows conventional Go versioning. Any version before 1.0.0 is considered unstable and the API may change. Backwards incompatible changes in unstable releases will, when possible, be deprecated first and documented in release notes.

## Support

For community support, join the [ProtoStudio Discord Community](https://proto.studio/social/discord). For commercial support, contact [Curioso Industries](https://curiosoindustries.com).