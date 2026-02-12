package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
)

// TestNewJWK_FromString tests creating a JWK from a JSON string.
func TestNewJWK_FromString(t *testing.T) {
	jwk, err := NewJWK(`{"kty":"RSA","n":"x","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Kty != "RSA" || jwk.N != "x" {
		t.Errorf("jwk = %+v", jwk)
	}
}

// TestNewJWK_FromStringInvalidJSON tests that NewJWK returns an error for invalid JSON.
func TestNewJWK_FromStringInvalidJSON(t *testing.T) {
	_, err := NewJWK(`{invalid}`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestNewJWK_FromECDSAPublicKey tests creating a JWK from an ECDSA public key.
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

// TestNewJWK_FromECDSAPrivateKey tests creating a JWK from an ECDSA private key.
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

// TestNewJWK_FromRSAPublicKey tests creating a JWK from an RSA public key.
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

// TestNewJWK_FromRSAPrivateKey tests creating a JWK from an RSA private key.
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

// TestNewJWK_FromJWKClone tests creating a JWK by cloning another JWK.
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

// TestNewJWK_UnsupportedType tests that NewJWK returns an error for an unsupported type.
func TestNewJWK_UnsupportedType(t *testing.T) {
	_, err := NewJWK(42)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

// TestJWK_String tests that String returns valid JSON for the JWK.
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

// TestJWK_String_MarshalError tests that String returns "{}" when JSON marshal fails.
func TestJWK_String_MarshalError(t *testing.T) {
	old := jsonMarshalJWK
	jsonMarshalJWK = func(interface{}) ([]byte, error) { return nil, errors.New("fail") }
	defer func() { jsonMarshalJWK = old }()
	j := &JWK{Kty: "RSA"}
	if s := j.String(); s != "{}" {
		t.Errorf("String() on marshal error = %q, want \"{}\"", s)
	}
}

// TestJWK_Clone tests that Clone returns a shallow copy of the JWK.
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

// TestJWK_Algorithm_RSA tests Algorithm for RS256, RS384, RS512 with an RSA JWK.
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
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Algorithm(RS256).Name(): %v", err)
	}
	if alg == nil || name != "RS256" {
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

// TestJWK_Algorithm_EC tests Algorithm for ES256 with a P-256 EC JWK.
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
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Algorithm(ES256).Name(): %v", err)
	}
	if alg == nil || name != "ES256" {
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

// TestJWK_getRSAKeys_NotRSA tests that getRSAKeys returns an error for a non-RSA JWK.
func TestJWK_getRSAKeys_NotRSA(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-256"}
	_, _, err := jwk.getRSAKeys()
	if err == nil {
		t.Fatal("getRSAKeys on EC should error")
	}
}

// TestJWK_Algorithm_RSA_GetRSAKeysFails tests that Algorithm returns an error when getRSAKeys fails.
func TestJWK_Algorithm_RSA_GetRSAKeysFails(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "!!!", E: "AQAB"}
	_, err := jwk.Algorithm("RS256")
	if err == nil {
		t.Fatal("Algorithm when getRSAKeys fails should error")
	}
}

// TestJWK_Algorithm_EC_GetECDSAKeysFails tests that Algorithm returns an error when getECDSAKeys fails.
func TestJWK_Algorithm_EC_GetECDSAKeysFails(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: "!!!", Y: "y"}
	_, err := jwk.Algorithm("ES256")
	if err == nil {
		t.Fatal("Algorithm when getECDSAKeys fails should error")
	}
}

// TestJWK_getECDSAKeys_NotEC tests that getECDSAKeys returns an error for a non-EC JWK.
func TestJWK_getECDSAKeys_NotEC(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "n", E: "e"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys on RSA should error")
	}
}

// TestJWK_getECDSAKeys_UnsupportedCurve tests that getECDSAKeys returns an error for an unsupported curve.
func TestJWK_getECDSAKeys_UnsupportedCurve(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-999", X: "x", Y: "y"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys with unsupported curve should error")
	}
}

// TestJWK_EC_P384_P521 tests getJWKCrv and getCurve for P-384 and P-521 via NewJWK and Algorithm.
func TestJWK_EC_P384_P521(t *testing.T) {
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}
	jwk384, err := NewJWK(key384)
	if err != nil {
		t.Fatalf("NewJWK P384: %v", err)
	}
	if jwk384.Crv != "P-384" {
		t.Errorf("P384 Crv = %s", jwk384.Crv)
	}
	alg, err := jwk384.Algorithm("ES384")
	if err != nil {
		t.Fatalf("Algorithm ES384: %v", err)
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Algorithm ES384 Name(): %v", err)
	}
	if name != "ES384" {
		t.Errorf("alg.Name() = %s", name)
	}

	key521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}
	jwk521, err := NewJWK(key521)
	if err != nil {
		t.Fatalf("NewJWK P521: %v", err)
	}
	if jwk521.Crv != "P-521" {
		t.Errorf("P521 Crv = %s", jwk521.Crv)
	}
	alg, err = jwk521.Algorithm("ES512")
	if err != nil {
		t.Fatalf("Algorithm ES512: %v", err)
	}
	name, err = alg.Name()
	if err != nil {
		t.Fatalf("Algorithm ES512 Name(): %v", err)
	}
	if name != "ES512" {
		t.Errorf("alg.Name() = %s", name)
	}
}

// TestJWK_algorithmEC_CurveMismatch tests that ES384 with a P-256 JWK returns an error.
func TestJWK_algorithmEC_CurveMismatch(t *testing.T) {
	// P-256 JWK with ES384 should error
	jwk, _ := NewJWK(`{"kty":"EC","crv":"P-256","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`)
	_, err := jwk.Algorithm("ES384")
	if err == nil {
		t.Fatal("ES384 with P-256 should error")
	}
}

// TestJWK_algorithmEC_ES256_WrongCurve tests that ES256 with a P-384 JWK returns an error.
func TestJWK_algorithmEC_ES256_WrongCurve(t *testing.T) {
	jwk384, _ := NewJWK(`{"kty":"EC","crv":"P-384","x":"x","y":"y"}`)
	_, err := jwk384.Algorithm("ES256")
	if err == nil {
		t.Fatal("ES256 with P-384 should error")
	}
}

// TestJWK_algorithmEC_ES512_WrongCurve tests that ES512 with a P-256 JWK returns an error.
func TestJWK_algorithmEC_ES512_WrongCurve(t *testing.T) {
	jwk256, _ := NewJWK(`{"kty":"EC","crv":"P-256","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`)
	_, err := jwk256.Algorithm("ES512")
	if err == nil {
		t.Fatal("ES512 with P-256 should error")
	}
}

// TestJWK_Algorithm_Unsupported tests that Algorithm returns an error for unsupported alg (e.g. HS256 with RSA JWK).
func TestJWK_Algorithm_Unsupported(t *testing.T) {
	jwk, _ := NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	_, err := jwk.Algorithm("HS256")
	if err == nil {
		t.Fatal("unsupported algorithm should error")
	}
}

// TestJWK_algorithmEC_UnknownAlg tests that algorithmEC returns an error for an unknown EC alg.
func TestJWK_algorithmEC_UnknownAlg(t *testing.T) {
	jwk, _ := NewJWK(`{"kty":"EC","crv":"P-256","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`)
	_, err := jwk.Algorithm("ES999")
	if err == nil {
		t.Fatal("unknown EC alg should error")
	}
}

// TestJWK_algorithmRSA_UnknownAlg tests that algorithmRSA returns an error for an unknown RSA alg.
func TestJWK_algorithmRSA_UnknownAlg(t *testing.T) {
	jwk, _ := NewJWK(`{"kty":"RSA","n":"YQ","e":"AQAB"}`)
	_, err := jwk.Algorithm("RS999")
	if err == nil {
		t.Fatal("unknown RSA alg should error")
	}
}

// TestJWK_getRSAKeys_InvalidN tests that getRSAKeys returns an error when N is invalid base64.
func TestJWK_getRSAKeys_InvalidN(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "!!!", E: "AQAB"}
	_, _, err := jwk.getRSAKeys()
	if err == nil {
		t.Fatal("getRSAKeys with invalid N should error")
	}
}

// TestJWK_getRSAKeys_InvalidE tests that getRSAKeys returns an error when E is invalid base64.
func TestJWK_getRSAKeys_InvalidE(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "YQ", E: "!!!"}
	_, _, err := jwk.getRSAKeys()
	if err == nil {
		t.Fatal("getRSAKeys with invalid E should error")
	}
}

// TestJWK_getRSAKeys_InvalidD tests that getRSAKeys returns an error when D is invalid base64.
func TestJWK_getRSAKeys_InvalidD(t *testing.T) {
	jwk := &JWK{Kty: "RSA", N: "YQ", E: "AQAB", D: "!!!"}
	_, _, err := jwk.getRSAKeys()
	if err == nil {
		t.Fatal("getRSAKeys with invalid D should error")
	}
}

// TestJWK_getECDSAKeys_InvalidX tests that getECDSAKeys returns an error when X is invalid base64.
func TestJWK_getECDSAKeys_InvalidX(t *testing.T) {
	// Valid Y from known P-256 JWK; invalid X
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: "!!!", Y: "d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys with invalid X should error")
	}
}

// TestJWK_getECDSAKeys_InvalidY tests that getECDSAKeys returns an error when Y is invalid base64.
func TestJWK_getECDSAKeys_InvalidY(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: "V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE", Y: "!!!"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys with invalid Y should error")
	}
}

// TestJWK_getECDSAKeys_InvalidD tests that getECDSAKeys returns an error when D is invalid base64.
func TestJWK_getECDSAKeys_InvalidD(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: "V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE", Y: "d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys", D: "!!!"}
	_, _, err := jwk.getECDSAKeys()
	if err == nil {
		t.Fatal("getECDSAKeys with invalid D should error")
	}
}
