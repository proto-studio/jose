package josevalidators_test

import (
	"context"
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
	s := josevalidators.JWS().String()
	if s != "JWSRuleSet" {
		t.Errorf("String() = %q", s)
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
