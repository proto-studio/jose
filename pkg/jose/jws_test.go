package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

// Requirements:
// - FullHeader returns an empty map if both protected and headers are unset.
// - FullHeader returns the unprotected header.
// TestGetFullHeader tests that FullHeader returns the protected header and protected takes priority.
func TestGetFullHeader(t *testing.T) {
	jws := jose.JWS{}

	head, err := jws.FullHeader()

	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	}

	jws.Header = make(jose.Header)
	jws.Header[jose.HeaderAlg] = "none"
	jws.Header[jose.HeaderKid] = "abc"

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else if alg := head[jose.HeaderAlg]; alg != "none" {
		t.Errorf("Expected Algorithm to be `%s`, got: %s", "none", alg)
	}

	jws.Protected = "eyJhbGciOiJIUzI1NiJ9"

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else {
		if alg := head[jose.HeaderAlg]; alg != "HS256" {
			t.Errorf("Expected Algorithm to be `%s`, got: %s", "HS256", alg)
		}
		if kid := head[jose.HeaderKid]; kid != "abc" {
			t.Errorf("Expected Kid to be `%s`, got: %s", "abc", kid)
		}
	}

	jws.Header = nil

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else {
		if alg := head[jose.HeaderAlg]; alg != "HS256" {
			t.Errorf("Expected Algorithm to be `%s`, got: %s", "HS256", alg)
		}
		if kid, ok := head[jose.HeaderKid]; ok {
			t.Errorf("Expected Kid to be nil, got: %s", kid)
		}
	}
}

// TestSignature_Decoded tests that Decoded returns the raw signature bytes from base64url.
func TestSignature_Decoded(t *testing.T) {
	sig := &jose.Signature{Signature: "YQ"} // base64url for 0x61 = 'a'
	dec, err := sig.Decoded()
	if err != nil {
		t.Fatalf("Decoded: %v", err)
	}
	if len(dec) != 1 || dec[0] != 'a' {
		t.Errorf("Decoded() = %v", dec)
	}
	sig.Signature = "!!!"
	if _, err := sig.Decoded(); err == nil {
		t.Error("expected error for invalid base64url")
	}
}

// TestJWS_Sign tests that Sign adds a signature with default typ.
func TestJWS_Sign(t *testing.T) {
	alg := jose.NewHS256([]byte("secret"))
	jws := &jose.JWS{Payload: "payload"}
	err := jws.Sign(alg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if jws.Signature == "" || jws.Protected == "" {
		t.Error("Sign did not set Signature/Protected")
	}
}

// TestJWS_SignWithType_NoAlg tests SignWithType with a single algorithm.
func TestJWS_SignWithType_NoAlg(t *testing.T) {
	jws := &jose.JWS{Payload: "x"}
	err := jws.SignWithType("JWT")
	if err == nil {
		t.Fatal("SignWithType with no alg should error")
	}
}

// TestJWS_SignWithType_ExpandFromFlat tests SignWithType when JWS already has a flat signature (add second alg expands to Signatures).
func TestJWS_SignWithType_ExpandFromFlat(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "e30"}
	err := jws.SignWithType("JWT", alg)
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	// Add one more signature: should move current to Signatures and append one
	err = jws.SignWithType("JWT", alg)
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}
	if jws.Signatures == nil || len(jws.Signatures) != 2 {
		t.Errorf("expected Signatures len 2, got %v", jws.Signatures)
	}
}

// TestJWS_SignWithType_MultipleAlgsEmpty tests SignWithType with multiple algs on empty JWS.
func TestJWS_SignWithType_MultipleAlgsEmpty(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "e30"}
	err := jws.SignWithType("JWT", alg, alg)
	if err != nil {
		t.Fatalf("SignWithType: %v", err)
	}
	if jws.Signatures == nil || len(jws.Signatures) != 2 {
		t.Errorf("expected Signatures len 2, got %v", jws.Signatures)
	}
}

// TestJWS_SignWithType_EmptyType tests SignWithType with an empty typ string.
func TestJWS_SignWithType_EmptyType(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "p"}
	err := jws.SignWithType("", alg)
	if err != nil {
		t.Fatalf("SignWithType: %v", err)
	}
	compact, err := jws.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact parts = %d", len(parts))
	}
}

// TestJWS_Compact_NoSignature_NoneDisabled tests that Compact returns an error when there is no signature and none is disabled.
func TestJWS_Compact_NoSignature_NoneDisabled(t *testing.T) {
	jws := &jose.JWS{Payload: "e30", Protected: "e30"}
	_, err := jws.Compact()
	if err == nil {
		t.Fatal("Compact without signature and None disabled should error")
	}
}

// TestJWS_Compact_NoSignature_NoneEnabled tests that Compact succeeds with two parts when none is enabled.
func TestJWS_Compact_NoSignature_NoneEnabled(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	jws := &jose.JWS{Payload: "e30", Protected: "e30"}
	s, err := jws.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if s != "e30.e30" {
		t.Errorf("Compact() = %s", s)
	}
}

// TestJWS_Compact_UnprotectedHeader tests that Compact returns an error when unprotected header is set.
func TestJWS_Compact_UnprotectedHeader(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "e30"}
	_ = jws.Sign(alg)
	jws.Header = jose.Header{"alg": "HS256"}
	_, err := jws.Compact()
	if err == nil {
		t.Fatal("Compact with unprotected header should error")
	}
}

// TestJWS_Compact_ThreePartReturn tests that Compact returns a three-part string when Signature is set.
func TestJWS_Compact_ThreePartReturn(t *testing.T) {
	jws := &jose.JWS{Protected: "e30", Payload: "e30", Signature: "e30"}
	s, err := jws.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != "e30" || parts[1] != "e30" || parts[2] != "e30" {
		t.Errorf("Compact() = %q, want three parts e30.e30.e30", s)
	}
}

// TestJWS_Flatten_MultipleSignatures tests that Flatten returns an error when there is more than one signature.
func TestJWS_Flatten_MultipleSignatures(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "e30"}
	_ = jws.SignWithType("JWT", alg, alg)
	err := jws.Flatten()
	if err == nil {
		t.Fatal("Flatten with multiple signatures should error")
	}
}

// TestJWS_Flatten_OneSignature tests that Flatten moves the first signature to the top level.
func TestJWS_Flatten_OneSignature(t *testing.T) {
	alg := jose.NewHS256([]byte("s"))
	jws := &jose.JWS{Payload: "e30"}
	_ = jws.SignWithType("JWT", alg)
	// Sign with single alg keeps flat form; set Signatures manually to test Flatten
	sig := jose.Signature{Protected: jws.Protected, Signature: jws.Signature}
	jws.Signatures = []jose.Signature{sig}
	jws.Protected = ""
	jws.Signature = ""
	err := jws.Flatten()
	if err != nil {
		t.Fatalf("Flatten: %v", err)
	}
	if jws.Signatures != nil {
		t.Error("Flatten should clear Signatures")
	}
	if jws.Signature == "" {
		t.Error("Flatten should set top-level Signature")
	}
}

// TestJWS_Verify_NilJWK tests that Verify returns false when the JWK is nil.
func TestJWS_Verify_NilJWK(t *testing.T) {
	jws := &jose.JWS{Payload: "e30", Protected: "e30", Signature: "e30"}
	if jws.Verify(nil) {
		t.Error("Verify(nil) should be false")
	}
}

// TestJWS_Verify_InvalidProtected tests that Verify returns false when the protected header is invalid.
func TestJWS_Verify_InvalidProtected(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	jws := &jose.JWS{Payload: "e30", Protected: "!!!", Signature: "e30"}
	if jws.Verify(jwk) {
		t.Error("Verify with bad protected should be false")
	}
}

// TestJWS_FullHeader_InvalidProtected tests that FullHeader returns an error for invalid base64 in protected.
func TestJWS_FullHeader_InvalidProtected(t *testing.T) {
	jws := &jose.JWS{Protected: "!!!", Payload: "e30"}
	_, err := jws.FullHeader()
	if err == nil {
		t.Error("FullHeader with invalid base64 protected should error")
	}
}

// TestJWS_FullHeader_InvalidJSONInProtected tests that FullHeader returns an error for invalid JSON in protected.
func TestJWS_FullHeader_InvalidJSONInProtected(t *testing.T) {
	// Valid base64 but content is not JSON
	notJSON := base64url.Encode([]byte("not json"))
	jws := &jose.JWS{Protected: notJSON, Payload: "e30"}
	_, err := jws.FullHeader()
	if err == nil {
		t.Error("FullHeader with non-JSON protected should error")
	}
}

// TestJWS_Verify_NoAlgInHeader tests that Verify returns false when the header has no alg.
func TestJWS_Verify_NoAlgInHeader(t *testing.T) {
	// Protected with no "alg" → Algorithm("") fails
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	// e30 = {} so header is empty
	jws := &jose.JWS{Protected: "e30", Payload: "e30", Signature: "e30"}
	if jws.Verify(jwk) {
		t.Error("Verify with no alg in header should be false")
	}
}

// TestJWS_Verify_UnsupportedAlgInHeader tests that Verify returns false when the header alg is unsupported.
func TestJWS_Verify_UnsupportedAlgInHeader(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	// Header with alg "INVALID" so Algorithm returns (nil, err)
	prot := base64url.Encode([]byte(`{"alg":"INVALID","typ":"JWT"}`))
	jws := &jose.JWS{Protected: prot, Payload: "e30", Signature: "e30"}
	if jws.Verify(jwk) {
		t.Error("Verify with unsupported alg in header should be false")
	}
}

// TestJWS_SignWithType_AlgSignError tests that SignWithType propagates an error when alg.Sign fails.
func TestJWS_SignWithType_AlgSignError(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jws := &jose.JWS{Payload: "e30"}
	alg := jose.NewES256(&key.PublicKey, nil) // no private key
	err := jws.SignWithType("JWT", alg)
	if err == nil {
		t.Fatal("SignWithType with alg that cannot sign should error")
	}
}

// TestJWS_Verify_ValidRSACompact tests Verify with a valid RSA-signed compact JWS.
func TestJWS_Verify_ValidRSACompact(t *testing.T) {
	// Use same token and JWK as josevalidators TestVerify to hit Verify path
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	parts := strings.Split(compact, ".")
	jws := &jose.JWS{Protected: parts[0], Payload: parts[1], Signature: parts[2]}
	if !jws.Verify(jwk) {
		t.Error("Verify(jwk) = false, want true")
	}
}

// TestJWS_Verify_NoSignatureNorSignatures tests that Verify returns false when there is no signature.
func TestJWS_Verify_NoSignatureNorSignatures(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	jws := &jose.JWS{Protected: "eyJhbGciOiJSUzI1NiJ9", Payload: "e30"} // no Signature, no Signatures
	if jws.Verify(jwk) {
		t.Error("Verify with no signature should be false")
	}
}

// TestJWS_Verify_ExpandedSignaturesPath tests Verify when JWS has Signatures (expanded form).
func TestJWS_Verify_ExpandedSignaturesPath(t *testing.T) {
	// Hit the Signatures != nil branch. FullHeader() uses jws.Protected so set it for expanded form.
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	parts := strings.Split(compact, ".")
	jws := &jose.JWS{
		Protected:  parts[0],
		Payload:    parts[1],
		Signatures: []jose.Signature{{Protected: parts[0], Signature: parts[2]}},
	}
	if !jws.Verify(jwk) {
		t.Error("Verify(jwk) with Signatures = false, want true")
	}
}

// TestJWS_Verify_ExpandedForm_NoMatch tests that Verify returns false when no signature matches the JWK.
func TestJWS_Verify_ExpandedForm_NoMatch(t *testing.T) {
	alg := jose.NewHS256([]byte("secret"))
	jws := &jose.JWS{Payload: "e30"}
	_ = jws.SignWithType("JWT", alg, alg) // expanded form with 2 sigs
	otherJWK, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`) // different key
	if jws.Verify(otherJWK) {
		t.Error("Verify with wrong JWK (expanded form) should be false")
	}
}

// TestParseCompactJWS tests parsing compact JWS strings.
func TestParseCompactJWS(t *testing.T) {
	// Valid 3-part (signature is base64url-encoded; "AQID" decodes to 3 bytes)
	compact := "eyJhbGciOiJIUzI1NiJ9.e30.AQID"
	jws, err := jose.ParseCompactJWS(compact)
	if err != nil {
		t.Fatalf("ParseCompactJWS: %v", err)
	}
	if jws.Protected != "eyJhbGciOiJIUzI1NiJ9" || jws.Payload != "e30" || jws.Signature != "AQID" {
		t.Errorf("ParseCompactJWS: got Protected=%q Payload=%q Signature=%q", jws.Protected, jws.Payload, jws.Signature)
	}
	// Valid 2-part (unsigned)
	compact2 := "eyJhbGciOiJub25lIn0.e30"
	jws2, err := jose.ParseCompactJWS(compact2)
	if err != nil {
		t.Fatalf("ParseCompactJWS(2-part): %v", err)
	}
	if jws2.Signature != "" {
		t.Errorf("expected empty signature, got %q", jws2.Signature)
	}
	// Invalid: one part
	_, err = jose.ParseCompactJWS("onlyone")
	if err == nil {
		t.Fatal("expected error for 1 part")
	}
	// Invalid: four parts
	_, err = jose.ParseCompactJWS("a.b.c.d")
	if err == nil {
		t.Fatal("expected error for 4 parts")
	}
	// Invalid base64 in header
	_, err = jose.ParseCompactJWS("!!!.e30.sig")
	if err == nil {
		t.Fatal("expected error for invalid protected")
	}
}
