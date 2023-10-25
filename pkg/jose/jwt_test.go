package jose_test

import (
	"testing"

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
