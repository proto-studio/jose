package josevalidators_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/testhelpers"
)

const compactString string = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.2_LNHFdcd5lv342TTvWSroucQY03R4ZBBM1Pwgvfqt8"

func checkJWS(b, a any) error {
	jws, ok := a.(*jose.JWS)
	if !ok {
		return errors.Errorf(errors.CodeInternal, context.Background(), "type mismatch", "Expected *jose.JWS, got %T", a)
	}
	if jws == nil {
		return errors.Errorf(errors.CodeInternal, context.Background(), "nil jws", "Expected jws to be non-nil")
	}
	return nil
}

// Requirements:
// - Implements interface.
func TestJWSRuleSet(t *testing.T) {
	ok := testhelpers.CheckRuleSetInterface[*jose.JWS](josevalidators.JWS())
	if !ok {
		t.Error("Expected rule set to be implemented")
		return
	}
}

// JWS Apply with output as interface{} (nil) hits the Interface+IsNil branch.
func TestJWS_Apply_OutputInterfaceNil(t *testing.T) {
	ruleSet := josevalidators.JWS()
	var output any
	err := ruleSet.Apply(context.Background(), compactString, &output)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if output == nil {
		t.Fatal("output should be set")
	}
	if _, ok := output.(*jose.JWS); !ok {
		t.Errorf("output type = %T", output)
	}
}

// JWS Apply with output of wrong type hits "Cannot assign" branch.
func TestJWS_Apply_OutputWrongType(t *testing.T) {
	ruleSet := josevalidators.JWS()
	var output int
	err := ruleSet.Apply(context.Background(), compactString, &output)
	if err == nil {
		t.Fatal("Apply with wrong output type should error")
	}
}

// JWS Evaluate with expanded form (Signatures != nil) and top-level set → validation errors.
func TestJWS_Evaluate_ExpandedFormErrors(t *testing.T) {
	ruleSet := josevalidators.JWS()
	jws := &jose.JWS{
		Signatures: []jose.Signature{{Protected: "e30", Signature: "x"}},
		Signature:  "also-set",
		Protected:  "e30",
		Payload:    "e30",
	}
	err := ruleSet.Evaluate(context.Background(), jws)
	if err == nil {
		t.Fatal("expected error when both Signatures and Signature/Protected set")
	}
}

// JWS Evaluate with Signatures != nil and Header set → "Header not allowed".
func TestJWS_Evaluate_ExpandedForm_HeaderNotAllowed(t *testing.T) {
	ruleSet := josevalidators.JWS()
	jws := &jose.JWS{
		Signatures: []jose.Signature{{Protected: "e30", Signature: "x"}},
		Header:     jose.Header{"alg": "HS256"},
		Payload:    "e30",
	}
	err := ruleSet.Evaluate(context.Background(), jws)
	if err == nil {
		t.Fatal("expected error when Signatures and Header both set")
	}
}

// JWS Evaluate with invalid base64 in Protected.
func TestJWS_Evaluate_InvalidProtectedBase64(t *testing.T) {
	ruleSet := josevalidators.JWS()
	jws := &jose.JWS{Protected: "!!!", Payload: "e30", Signature: "e30"}
	err := ruleSet.Evaluate(context.Background(), jws)
	if err == nil {
		t.Fatal("expected error for invalid protected base64")
	}
}

// JWS Evaluate with invalid base64 in Payload.
func TestJWS_Evaluate_InvalidPayloadBase64(t *testing.T) {
	ruleSet := josevalidators.JWS()
	jws := &jose.JWS{Protected: "e30", Payload: "!!!", Signature: "e30"}
	err := ruleSet.Evaluate(context.Background(), jws)
	if err == nil {
		t.Fatal("expected error for invalid payload base64")
	}
}

// Requirements:
// - Parses compact string.
// - Signature matches.
// - Protected matches.
// - Headers is nil.
// - JWS is flat (Signatures is nil).
func TestJWSParseCompact(t *testing.T) {
	ruleSet := josevalidators.JWS()

	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compactString, &jws)

	if err != nil {
		t.Fatalf("Expected error to be nil, got: %s", err)
	}

	if jws.Header != nil {
		t.Errorf("Expected header to be nil, got: %v", jws.Header)
	}

	if jws.Signatures != nil {
		t.Errorf("Expected signatures to be nil, got: %v", jws.Signatures)
	}

	parts := strings.Split(compactString, ".")

	if jws.Signature != parts[2] {
		t.Errorf("Expected signatures to be %s, got: %s", parts[2], jws.Signature)
	}

	if jws.Payload != parts[1] {
		t.Errorf("Expected payload to be %s, got: %s", parts[1], jws.Payload)
	}

	if jws.Protected != parts[0] {
		t.Errorf("Expected payload to be %s, got: %s", parts[0], jws.Protected)
	}
}

// Requirements:

// Requirements:
// - Fails if less than 2 parts.
func TestJWSParseNoPayload(t *testing.T) {
	ruleSet := josevalidators.JWS()
	val := "eyJhbGciOiJIUzI1NiJ9"
	testhelpers.MustNotApply(t, ruleSet.Any(), val, errors.CodePattern)
}

// Requirements:
// - Fails if less more than 3 parts.
func TestJWSParseTooManyParts(t *testing.T) {
	ruleSet := josevalidators.JWS()
	val := compactString + ".eyJhbGciOiJIUzI1NiJ9"
	testhelpers.MustNotApply(t, ruleSet.Any(), val, errors.CodePattern)
}

// Requirements:
// - Fails if 2 parts and None is not enabled
// - Succeeds if 2 parts and none is enabled
func TestJWSParseNone(t *testing.T) {
	ruleSet := josevalidators.JWS()
	val := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"

	testhelpers.MustNotApply(t, ruleSet.Any(), val, errors.CodePattern)

	jose.EnableNone()
	defer jose.DisableNone()
	testhelpers.MustApplyFunc(t, ruleSet.Any(), val, nil, checkJWS)
}

// Requirements:
// - Header must be Base 64 URL encoded
// - Payload must be base 64 URL encoded
// - Signature must be base 64 URL encoded
// - Paths must match
// - Returns all errors
func TestBase64URL(t *testing.T) {
	ruleSet := josevalidators.JWS()

	parts := strings.Split(compactString, ".")

	testhelpers.MustApplyFunc(t, ruleSet.Any(), strings.Join(parts, "."), nil, checkJWS)

	backup := parts[0]
	parts[0] = parts[0] + "/"

	err := testhelpers.MustNotApply(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationError)
		unwrap := errors.Unwrap(valErr)
		l := len(unwrap)
		if l == 0 {
			l = 1
		}
		if l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)
		}
		if p := valErr.Path(); p != "/header" {
			t.Errorf("Expected path to be %s, got %s", "/header", p)
		}
	}
	parts[0] = backup

	backup = parts[1]
	parts[1] = parts[1] + "/"

	err = testhelpers.MustNotApply(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationError)
		unwrap := errors.Unwrap(valErr)
		l := len(unwrap)
		if l == 0 {
			l = 1
		}
		if l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)
		}
		if p := valErr.Path(); p != "/payload" {
			t.Errorf("Expected path to be %s, got %s", "/payload", p)
		}
	}
	parts[1] = backup

	parts[2] = parts[2] + "/"

	err = testhelpers.MustNotApply(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationError)
		unwrap := errors.Unwrap(valErr)
		l := len(unwrap)
		if l == 0 {
			l = 1
		}
		if l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)
		}
		if p := valErr.Path(); p != "/signature" {
			t.Errorf("Expected path to be %s, got %s", "/signature", p)
		}
	}

	parts[1] = parts[1] + "/"

	err = testhelpers.MustNotApply(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationError)
		unwrap := errors.Unwrap(valErr)
		l := len(unwrap)
		if l == 0 {
			l = 1
		}
		if l != 2 {
			t.Errorf("Expected %d error, got %s", 2, err)
		}
	}

}

func TestVerify(t *testing.T) {
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("Expected err to be nil, got: %s", err)
	}

	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)

	var jws *jose.JWS
	verr := ruleSet.Apply(context.Background(), `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`, &jws)

	if verr != nil {
		t.Errorf("Expected validation errors to be ni, got: %s", verr)
	}
}

func TestJWSRuleSet_Required(t *testing.T) {
	rs := josevalidators.JWS()
	if rs.Required() {
		t.Error("default Required() should be false")
	}
}

func TestJWSRuleSet_WithRequired(t *testing.T) {
	rs := josevalidators.JWS().WithRequired()
	if rs == nil {
		t.Fatal("WithRequired returned nil")
	}
	if !rs.Required() {
		t.Error("WithRequired().Required() should be true")
	}
	// Second WithRequired when already true returns same (coverage: early return)
	rs2 := rs.WithRequired()
	if rs2 != rs {
		t.Error("WithRequired when already required should return same rule set")
	}
}

func TestJWSRuleSet_WithRule_WithRuleFunc(t *testing.T) {
	rs := josevalidators.JWS().
		WithRuleFunc(func(_ context.Context, _ *jose.JWS) errors.ValidationError {
			return nil
		})
	if rs == nil {
		t.Fatal("WithRuleFunc returned nil")
	}
}

func TestJWSRuleSet_String(t *testing.T) {
	// Base rule set
	if s := josevalidators.JWS().String(); s != "JWSRuleSet" {
		t.Errorf("JWS().String() = %q, want JWSRuleSet", s)
	}
	// WithRequired and WithJWK / WithJWKS show in chain
	rs := josevalidators.JWS().WithRequired()
	if s := rs.String(); s != "JWSRuleSet.WithRequired()" {
		t.Errorf("JWS().WithRequired().String() = %q, want JWSRuleSet.WithRequired()", s)
	}
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"x","n":"n","e":"AQAB"}`)
	rs = josevalidators.JWS().WithJWK(jwk)
	if s := rs.String(); s != "JWSRuleSet.WithJWK()" {
		t.Errorf("JWS().WithJWK().String() = %q, want JWSRuleSet.WithJWK()", s)
	}
	jwks := jose.NewJWKS(jwk)
	rs = josevalidators.JWS().WithJWKS(jwks)
	if s := rs.String(); s != "JWSRuleSet.WithJWKS()" {
		t.Errorf("JWS().WithJWKS().String() = %q, want JWSRuleSet.WithJWKS()", s)
	}
	rs = josevalidators.JWS().WithJWKSURL("https://example.com/keys")
	if s := rs.String(); s != "JWSRuleSet.WithJWKSURL(...)" {
		t.Errorf("JWS().WithJWKSURL().String() = %q, want JWSRuleSet.WithJWKSURL(...)", s)
	}
	// WithVerifyFunc shows rule label
	rs = josevalidators.JWS().WithVerifyFunc(func(context.Context, jose.Header) *jose.JWK { return jwk })
	if s := rs.String(); s != "JWSRuleSet.WithVerifyFunc(...)" {
		t.Errorf("JWS().WithVerifyFunc().String() = %q, want JWSRuleSet.WithVerifyFunc(...)", s)
	}
	// Chained
	rs = josevalidators.JWS().WithRequired().WithJWK(jwk)
	if s := rs.String(); s != "JWSRuleSet.WithRequired().WithJWK()" {
		t.Errorf("chained String() = %q, want JWSRuleSet.WithRequired().WithJWK()", s)
	}
}

func TestJWS_Evaluate_SignaturesAndSignatureSet(t *testing.T) {
	// When Signatures != nil, having Signature set should add error
	ctx := context.Background()
	jws := &jose.JWS{
		Protected:  "eyJhbGciOiJIUzI1NiJ9",
		Payload:    "e30",
		Signature:  "x",
		Signatures: []jose.Signature{{Protected: "eyJhbGciOiJIUzI1NiJ9", Signature: "x"}},
	}
	err := josevalidators.JWS().Evaluate(ctx, jws)
	if err == nil {
		t.Error("expected error when both Signature and Signatures set")
	}
}

func TestJWS_Apply_NilOutput(t *testing.T) {
	ctx := context.Background()
	err := josevalidators.JWS().Apply(ctx, compactString, nil)
	if err == nil {
		t.Error("expected error when output is nil")
	}
}

func TestJWS_Apply_NonPointerOutput(t *testing.T) {
	ctx := context.Background()
	var jws jose.JWS
	err := josevalidators.JWS().Apply(ctx, compactString, jws)
	if err == nil {
		t.Error("expected error when output is not a pointer")
	}
}

func TestJWS_WithVerifyJWK_VerifyFails(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"other","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)
	// Valid compact form but JWK is different key → Verify fails
	compact := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.e30"
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("expected error when signature verification fails")
	}
}

// verifyRule: FullHeader error path (bad protected)
func TestJWS_WithVerifyJWK_BadProtected(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)
	compact := "!!!.eyJzdWIiOiJ0ZXN0In0.e30" // invalid header base64
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("expected error when protected header is invalid")
	}
}

// verifyRule success path: valid signed compact + matching JWK → Apply succeeds.
func TestJWS_Apply_WithVerifyJWK_Success(t *testing.T) {
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)
	var out *jose.JWS
	err = ruleSet.Apply(context.Background(), compact, &out)
	if err != nil {
		t.Fatalf("Apply with valid signed compact and matching JWK should succeed: %v", err)
	}
	if out == nil || out.Payload == "" {
		t.Error("expected JWS to be populated")
	}
}

// verifyRule: alg empty path (header has no alg key)
func TestJWS_WithVerifyJWK_AlgEmpty(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)
	// e30 = {} so header has no "alg"
	compact := "e30.e30.e30"
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("expected error when alg is empty (JWS must be signed)")
	}
}

// verifyRule: alg none path
func TestJWS_WithVerifyJWK_AlgNone(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	jwk, _ := jose.NewJWK(`{"kty":"RSA","n":"n","e":"AQAB"}`)
	ruleSet := josevalidators.JWS().WithVerifyJWK(jwk)
	compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("expected error when alg is none (JWS must be signed)")
	}
}

// verifyRule: fn returns nil JWK → Verify(nil) is false
func TestJWS_WithVerifyFunc_ReturnsNilJWK(t *testing.T) {
	ruleSet := josevalidators.JWS().WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return nil })
	compact := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.e30"
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("expected error when verify func returns nil JWK")
	}
}

func TestJWS_WithJWKS_Success(t *testing.T) {
	// Same compact and JWK as TestJWS_Apply_WithVerifyJWK_Success (token has kid RSA20240212)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwks := jose.NewJWKS(jwk)
	ruleSet := josevalidators.JWS().WithJWKS(jwks)
	var out *jose.JWS
	err = ruleSet.Apply(context.Background(), compact, &out)
	if err != nil {
		t.Fatalf("WithJWKS Apply: %v", err)
	}
	if out == nil || out.Payload == "" {
		t.Error("expected JWS to be populated")
	}
}

func TestJWS_WithJWKS_KeyNotFound(t *testing.T) {
	// Token has kid RSA20240212; JWKS has a key with different kid
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"other","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := jose.NewJWKS(jwk)
	ruleSet := josevalidators.JWS().WithJWKS(jwks)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.e30`
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("WithJWKS when kid not in set should error")
	}
}

// WithJWK and WithJWKS conflict: most recently called wins.
func TestJWS_WithJWKS_WithJWK_Conflict(t *testing.T) {
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := jose.NewJWKS(jwk)
	var jws *jose.JWS
	// WithJWKS then WithJWK: WithJWK wins (replaces WithJWKS in chain)
	ruleSet := josevalidators.JWS().WithJWKS(jwks).WithJWK(jwk)
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err != nil {
		t.Errorf("WithJWK after WithJWKS should win and succeed: %v", err)
	}
	// WithJWK then WithJWKS: WithJWKS wins
	ruleSet2 := josevalidators.JWS().WithJWK(jwk).WithJWKS(jwks)
	err = ruleSet2.Apply(context.Background(), compact, &jws)
	if err != nil {
		t.Errorf("WithJWKS after WithJWK should win and succeed: %v", err)
	}
}

func TestJWS_WithJWKSURL_Success(t *testing.T) {
	// Same compact and JWK as TestJWS_WithJWKS_Success (token has kid RSA20240212)
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwks := jose.NewJWKS(jwk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks.String()))
	}))
	defer server.Close()

	ruleSet := josevalidators.JWS().WithJWKSURL(server.URL)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	var out *jose.JWS
	err = ruleSet.Apply(context.Background(), compact, &out)
	if err != nil {
		t.Fatalf("WithJWKSURL Apply: %v", err)
	}
	if out == nil || out.Payload == "" {
		t.Error("expected JWS to be populated")
	}
}

func TestJWS_WithJWKSURL_KeyNotFound(t *testing.T) {
	// JWKS at URL has different kid than token
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"other","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := jose.NewJWKS(jwk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks.String()))
	}))
	defer server.Close()

	ruleSet := josevalidators.JWS().WithJWKSURL(server.URL)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.e30`
	var jws *jose.JWS
	err := ruleSet.Apply(context.Background(), compact, &jws)
	if err == nil {
		t.Fatal("WithJWKSURL when kid not in set should error")
	}
}
