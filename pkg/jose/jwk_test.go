package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestNewJWK_FromString(t *testing.T) {
	jwk, err := NewJWK(`{"kty":"RSA","n":"x","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "RSA" || jwk.N != "x" {
		t.Errorf("jwk = %+v", jwk)
	}
}

func TestNewJWK_FromStringInvalidJSON(t *testing.T) {
	_, err := NewJWK(`{invalid}`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewJWK_FromECDSAPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := NewJWK(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		t.Errorf("jwk = %+v", jwk)
	}
	jwk2, err := NewJWK(key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK(value): %v", err)
	}
	if jwk2.Kty != "EC" {
		t.Errorf("jwk2 = %+v", jwk2)
	}
}

func TestNewJWK_FromECDSAPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := NewJWK(key)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "EC" || jwk.D == "" {
		t.Errorf("jwk = %+v", jwk)
	}
}

func TestNewJWK_FromRSAPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := NewJWK(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
		t.Errorf("jwk = %+v", jwk)
	}
	jwk2, err := NewJWK(key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK(value): %v", err)
	}
	if jwk2.Kty != "RSA" {
		t.Errorf("jwk2 = %+v", jwk2)
	}
}

func TestNewJWK_FromRSAPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := NewJWK(key)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "RSA" {
		t.Errorf("jwk = %+v", jwk)
	}
	jwk2, err := NewJWK(*key)
	if err != nil {
		t.Fatalf("NewJWK(value): %v", err)
	}
	if jwk2.Kty != "RSA" {
		t.Errorf("jwk2 = %+v", jwk2)
	}
}

func TestNewJWK_FromJWKClone(t *testing.T) {
	orig := &JWK{Kty: "RSA", N: "n", E: "e", Kid: "x"}
	jwk, err := NewJWK(orig)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk == orig {
		t.Error("Clone should return new pointer")
	}
	if jwk.Kty != orig.Kty || jwk.N != orig.N {
		t.Errorf("jwk = %+v", jwk)
	}
	jwk2, err := NewJWK(*orig)
	if err != nil {
		t.Fatalf("NewJWK(value): %v", err)
	}
	if jwk2.Kty != "RSA" {
		t.Errorf("jwk2 = %+v", jwk2)
	}
}

func TestNewJWK_UnsupportedType(t *testing.T) {
	_, err := NewJWK(42)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestJWK_String(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "n", E: "e"}
	s := jwk.String()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("String() not valid JSON: %v", err)
	}
	if m["kty"] != "RSA" {
		t.Errorf("String() = %s", s)
	}
}

func TestJWK_Clone(t *testing.T) {
	orig := &JWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y", N: "n", E: "e"}
	c := orig.Clone()
	if c == orig {
		t.Error("Clone should return new pointer")
	}
	if c.Kty != orig.Kty || c.X != orig.X {
		t.Errorf("Clone() = %+v", c)
	}
}

func TestJWK_Algorithm_RSA(t *testing.T) {
	// Use known-good RSA JWK (public only)
	jwk, err := NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	alg, err := jwk.Algorithm("RS256")
	if err != nil {
		t.Fatalf("Algorithm(RS256): %v", err)
	}
	if alg == nil || alg.Name() != "RS256" {
		t.Errorf("Algorithm(RS256) = %v", alg)
	}
	alg, err = jwk.Algorithm("RS384")
	if err != nil {
		t.Fatalf("Algorithm(RS384): %v", err)
	}
	if alg == nil {
		t.Errorf("Algorithm(RS384) = nil")
	}
	alg, err = jwk.Algorithm("RS512")
	if err != nil {
		t.Fatalf("Algorithm(RS512): %v", err)
	}
	if alg == nil {
		t.Errorf("Algorithm(RS512) = nil")
	}
	_, err = jwk.Algorithm("RS999")
	if err == nil {
		t.Fatal("expected error for unknown RSA alg")
	}
	_, err = jwk.Algorithm("invalid")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestJWK_Algorithm_EC(t *testing.T) {
	const ecJWK = `{"kty":"EC","crv":"P-256","kid":"EC20240131","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`
	jwk, err := NewJWK(ecJWK)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	alg, err := jwk.Algorithm("ES256")
	if err != nil {
		t.Fatalf("Algorithm(ES256): %v", err)
	}
	if alg == nil || alg.Name() != "ES256" {
		t.Errorf("Algorithm(ES256) = %v", alg)
	}
	_, err = jwk.Algorithm("ES384")
	if err == nil {
		t.Fatal("ES384 with P-256 curve should error")
	}
	_, err = jwk.Algorithm("ES999")
	if err == nil {
		t.Fatal("expected error for unknown EC alg")
	}
}

func TestJWK_getRSAKeys_NotRSA(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-256"}
	_, _, err := jwk.getRSAKeys()
	if err == nil {
		t.Fatal("getRSAKeys on EC should error")
	}
}

func TestJWK_getECDSAKeys_NotEC(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "n", E: "e"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys on RSA should error")
	}
}

func TestJWK_getECDSAKeys_UnsupportedCurve(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-999", X: "x", Y: "y"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys with unsupported curve should error")
	}
}
