package jose

import (
	"encoding/json"
	"testing"
)

func TestJWKS(t *testing.T) {
	// Test NewJWKS and Add
	jwk1 := &JWK{Kty: "RSA", N: "value1", E: "value2", Kid: "key1"}
	jwk2 := &JWK{Kty: "EC", Crv: "P-256", X: "valueX", Y: "valueY", Kid: "key2"}

	jwks := NewJWKS(jwk1)
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected length of jwks.Keys to be 1, got %d", len(jwks.Keys))
	}

	jwks.Add(jwk2)
	if len(jwks.Keys) != 2 {
		t.Errorf("Expected length of jwks.Keys to be 2, got %d", len(jwks.Keys))
	}

	// Test GetByKid
	foundJWK := jwks.GetByKid("key1")
	if foundJWK == nil || foundJWK.Kid != "key1" {
		t.Errorf("Expected to find JWK with kid 'key1', got %v", foundJWK)
	}

	nonExistentJWK := jwks.GetByKid("nonExistentKey")
	if nonExistentJWK != nil {
		t.Errorf("Expected to not find JWK with kid 'nonExistentKey', got %v", nonExistentJWK)
	}

	// Test String (JSON representation) by decoding it back
	jsonStr := jwks.String()
	var decodedJWKS JWKS
	if err := json.Unmarshal([]byte(jsonStr), &decodedJWKS); err != nil {
		t.Errorf("Failed to decode JWKS JSON: %v", err)
	}

	if len(decodedJWKS.Keys) != 2 {
		t.Errorf("Expected length of decodedJWKS.Keys to be 2, got %d", len(decodedJWKS.Keys))
	}
}
