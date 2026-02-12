# JOSE

[![Tests](https://github.com/proto-studio/jose/actions/workflows/tests.yml/badge.svg)](https://github.com/proto-studio/jose/actions/workflows/tests.yml)
[![GoDoc](https://pkg.go.dev/badge/proto.zip/studio/jose)](https://pkg.go.dev/proto.zip/studio/jose)
[![codecov](https://codecov.io/gh/proto-studio/jose/graph/badge.svg)](https://codecov.io/gh/proto-studio/jose)
[![Go Report Card](https://goreportcard.com/badge/proto.zip/studio/jose)](https://goreportcard.com/report/proto.zip/studio/jose)
[![Discord Chat](https://img.shields.io/badge/Discord-chat-blue?logo=Discord&logoColor=white)](https://proto.studio/social/discord)

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
