package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

// TestNewJWT tests that NewJWT creates a JWT with the given algorithm and empty claims.
func TestNewJWT(t *testing.T) {
	jwt := jose.NewJWT(&mockAlgorithm{})
	if jwt == nil {
		t.Fatal("Expected JWT to be initialized, but got nil")
	}
	if len(jwt.Claims) != 0 {
		t.Fatalf("Expected Claims to be empty, but got %d items", len(jwt.Claims))
	}
}

// TestJWTCompact tests that Compact produces a three-part string when signed.
func TestJWTCompact(t *testing.T) {
	jwt := jose.NewJWT(&mockAlgorithm{})
	compact, err := jwt.Compact()
	if err != nil {
		t.Fatalf("Failed to get compact JWT: %v", err)
	}
	if compact == "" {
		t.Fatal("Expected compact JWT, but got empty string")
	}
}

// TestJWTJWS tests that JWS returns a signed JWS with typ JWT.
func TestJWTJWS(t *testing.T) {
	jwt := jose.NewJWT(&mockAlgorithm{})
	jws, err := jwt.JWS()
	if err != nil {
		t.Fatalf("Failed to get JWS: %v", err)
	}
	if jws == nil {
		t.Fatal("Expected JWS to be initialized, but got nil")
	}
	if jws.Payload == "" {
		t.Fatal("Expected JWS payload, but got empty string")
	}
}

// TestJWTHS256 tests signing a JWT with HS256 and compacting it.
func TestJWTHS256(t *testing.T) {
	alg := jose.NewH256([]byte("my-secret"))

	jwt := jose.NewJWT(alg)
	jwt.Claims[jose.SubjectKey] = "test"

	compact, err := jwt.Compact()
	if err != nil {
		t.Fatalf("Failed to get compact JWT: %v", err)
	}

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.fpC_knmi5R_YfNFGuyQQYqH4Ge0-IDdIoIgaOaqCIg0"

	if compact != expected {
		t.Fatalf("Incorrect signed JWT, expected %s got %s", expected, compact)
	}
}

// TestJWTFromJWS_FlattenError tests that JWTFromJWS returns an error when Flatten fails.
func TestJWTFromJWS_FlattenError(t *testing.T) {
	// Multiple signatures so Flatten() fails
	jws := &jose.JWS{Payload: "e30", Signatures: []jose.Signature{{}, {}}}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with multiple signatures should error")
	}
}

// TestJWTFromJWS_InvalidPayload tests that JWTFromJWS returns an error for invalid base64 payload.
func TestJWTFromJWS_InvalidPayload(t *testing.T) {
	jws := &jose.JWS{Protected: "e30", Payload: "!!!", Signature: "e30"}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with invalid payload should error")
	}
}

// TestJWTFromJWS_InvalidJSONClaims tests that JWTFromJWS returns an error for invalid JSON in the payload.
func TestJWTFromJWS_InvalidJSONClaims(t *testing.T) {
	// Payload is base64url of non-JSON
	payloadB64 := base64url.Encode([]byte("not json"))
	jws := &jose.JWS{Protected: "e30", Payload: payloadB64, Signature: "e30"}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with non-JSON payload should error")
	}
}

// TestJWT_JWS_NoAlg tests that JWS succeeds with no signature when Alg is nil.
func TestJWT_JWS_NoAlg(t *testing.T) {
	jwt := jose.NewJWT(nil)
	jwt.Claims["sub"] = "test"
	jws, err := jwt.JWS()
	if err != nil {
		t.Fatalf("JWS: %v", err)
	}
	if jws.Payload == "" {
		t.Error("JWS payload should be set")
	}
	if jws.Signature != "" {
		t.Error("JWS with nil alg should not have signature")
	}
}

// TestJWT_Compact_NoAlg_NoneDisabled tests that Compact returns an error when Alg is nil and none is disabled.
func TestJWT_Compact_NoAlg_NoneDisabled(t *testing.T) {
	jwt := jose.NewJWT(nil)
	jwt.Claims["x"] = "y"
	_, err := jwt.Compact()
	if err == nil {
		t.Fatal("Compact with nil alg and None disabled should error")
	}
}

// TestJWT_JWS_MarshalError tests that JWS returns an error when claims cannot be marshaled.
func TestJWT_JWS_MarshalError(t *testing.T) {
	// Claims that cannot be JSON-marshaled (channel is not supported by encoding/json).
	jwt := jose.NewJWT(nil)
	jwt.Claims["bad"] = make(chan int)
	_, err := jwt.JWS()
	if err == nil {
		t.Fatal("JWS with unmarshalable claims should error")
	}
}

// TestJWT_Compact_JWSError tests that Compact propagates an error from JWS().
func TestJWT_Compact_JWSError(t *testing.T) {
	jwt := jose.NewJWT(nil)
	jwt.Claims["bad"] = make(chan int)
	_, err := jwt.Compact()
	if err == nil {
		t.Fatal("Compact when JWS() fails should error")
	}
}

// TestJWT_JWS_SignError tests that JWS propagates an error when Sign fails.
func TestJWT_JWS_SignError(t *testing.T) {
	jwt := jose.NewJWT(&mockAlgorithm{SignErr: errors.New("sign failed")})
	jwt.Claims["sub"] = "test"
	_, err := jwt.JWS()
	if err == nil {
		t.Fatal("JWS when Sign fails should error")
	}
}

// TestECKeyCreateAndSignedJWT is a script-style test: it creates a new EC key,
// dumps the JWK to stdout, then creates a JWT signed with that key and dumps
// the compact JWT to stdout. Run with: go test -run TestECKeyCreateAndSignedJWT -v ./pkg/jose
func TestECKeyCreateAndSignedJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	jwkPrivate, err := jose.NewJWK(privateKey)
	if err != nil {
		t.Fatalf("JWK from key: %v", err)
	}
	jwkPublic, err := jose.NewJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("public JWK from key: %v", err)
	}
	jwkPublic.Alg = "ES256"
	jwkPublic.Use = "sig"
	jwkPublic.Kid = "ec-test-key"

	jwkJSON, err := json.MarshalIndent(jwkPublic, "", "  ")
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	fmt.Fprintln(os.Stdout, "--- JWK (public) ---")
	os.Stdout.Write(jwkJSON)
	fmt.Fprintln(os.Stdout, "")

	alg, err := jwkPrivate.Algorithm("ES256")
	if err != nil {
		t.Fatalf("algorithm from JWK: %v", err)
	}

	jwt := jose.NewJWT(alg)
	jwt.Claims[jose.SubjectKey] = "test-subject"
	jwt.Claims[jose.IssuerKey] = "test-issuer"
	jwt.Claims[jose.IssuedAtKey] = 1700000000

	compact, err := jwt.Compact()
	if err != nil {
		t.Fatalf("compact JWT: %v", err)
	}
	fmt.Fprintln(os.Stdout, "--- Signed JWT ---")
	fmt.Fprintln(os.Stdout, compact)
}
