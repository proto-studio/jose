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

func TestJWKS_AlgorithmsFor(t *testing.T) {
	// RSA key that can produce RS256
	jwk, _ := NewJWK(`{"kty":"RSA","kid":"r1","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := NewJWKS(jwk)
	head := Header{"alg": "RS256", "kid": "r1"}
	algs := jwks.AlgorithmsFor(head)
	if len(algs) != 1 {
		t.Errorf("AlgorithmsFor len = %d, want 1", len(algs))
	}
	head["kid"] = "nonexistent"
	algs = jwks.AlgorithmsFor(head)
	if len(algs) != 0 {
		t.Errorf("AlgorithmsFor(nonexistent kid) len = %d, want 0", len(algs))
	}
}
