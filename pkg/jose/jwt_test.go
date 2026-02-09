package jose_test

import (
	"testing"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func TestNewJWT(t *testing.T) {
	jwt := jose.NewJWT(&mockAlgorithm{})
	if jwt == nil {
		t.Fatal("Expected JWT to be initialized, but got nil")
	}
	if len(jwt.Claims) != 0 {
		t.Fatalf("Expected Claims to be empty, but got %d items", len(jwt.Claims))
	}
}

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

func TestJWTFromJWS_FlattenError(t *testing.T) {
	// Multiple signatures so Flatten() fails
	jws := &jose.JWS{Payload: "e30", Signatures: []jose.Signature{{}, {}}}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with multiple signatures should error")
	}
}

func TestJWTFromJWS_InvalidPayload(t *testing.T) {
	jws := &jose.JWS{Protected: "e30", Payload: "!!!", Signature: "e30"}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with invalid payload should error")
	}
}

func TestJWTFromJWS_InvalidJSONClaims(t *testing.T) {
	// Payload is base64url of non-JSON
	payloadB64 := base64url.Encode([]byte("not json"))
	jws := &jose.JWS{Protected: "e30", Payload: payloadB64, Signature: "e30"}
	_, err := jose.JWTFromJWS(jws)
	if err == nil {
		t.Fatal("JWTFromJWS with non-JSON payload should error")
	}
}

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

func TestJWT_Compact_NoAlg_NoneDisabled(t *testing.T) {
	jwt := jose.NewJWT(nil)
	jwt.Claims["x"] = "y"
	_, err := jwt.Compact()
	if err == nil {
		t.Fatal("Compact with nil alg and None disabled should error")
	}
}
