package josevalidators_test

import (
	"strings"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/testhelpers"
)

const compactString string = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.2_LNHFdcd5lv342TTvWSroucQY03R4ZBBM1Pwgvfqt8"

func jwsValidCheck(a, b any) error {
	return nil
}

// Requirements:
// - Implements interface.
func TestJWSRuleSet(t *testing.T) {
	ok := testhelpers.CheckRuleSetInterface[*jose.JWS](josevalidators.NewJWS())
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
	ruleSet := josevalidators.NewJWS()

	jws, err := ruleSet.Validate(compactString)

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
	ruleSet := josevalidators.NewJWS()
	val := "eyJhbGciOiJIUzI1NiJ9"
	testhelpers.MustBeInvalid(t, ruleSet.Any(), val, errors.CodePattern)
}

// Requirements:
// - Fails if less more than 3 parts.
func TestJWSParseTooManyParts(t *testing.T) {
	ruleSet := josevalidators.NewJWS()
	val := compactString + ".eyJhbGciOiJIUzI1NiJ9"
	testhelpers.MustBeInvalid(t, ruleSet.Any(), val, errors.CodePattern)
}

// Requirements:
// - Fails if 2 parts and None is not enabled
// - Succeeds if 2 parts and none is enabled
func TestJWSParseNone(t *testing.T) {
	ruleSet := josevalidators.NewJWS()
	val := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"

	testhelpers.MustBeInvalid(t, ruleSet.Any(), val, errors.CodePattern)

	jose.EnableNone()
	defer jose.EnableNone()
	testhelpers.MustBeValidFunc(t, ruleSet.Any(), val, nil, jwsValidCheck)
}

// Requirements:
// - Header must be Base 64 URL encoded
// - Payload must be base 64 URL encoded
// - Signature must be base 64 URL encoded
// - Paths must match
// - Returns all errors
func TestBase64URL(t *testing.T) {
	ruleSet := josevalidators.NewJWS()

	parts := strings.Split(compactString, ".")

	testhelpers.MustBeValidFunc(t, ruleSet.Any(), strings.Join(parts, "."), nil, jwsValidCheck)

	backup := parts[0]
	parts[0] = parts[0] + "/"

	err := testhelpers.MustBeInvalid(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationErrorCollection)

		if l := len(valErr); l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)

		}
		if p := valErr.First().Path(); p != "/header" {
			t.Errorf("Expected path to be %s, got %s", "/header", p)
		}
	}
	parts[0] = backup

	backup = parts[1]
	parts[1] = parts[1] + "/"

	err = testhelpers.MustBeInvalid(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationErrorCollection)

		if l := len(valErr); l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)

		}
		if p := valErr.First().Path(); p != "/payload" {
			t.Errorf("Expected path to be %s, got %s", "/payload", p)
		}
	}
	parts[1] = backup

	parts[2] = parts[2] + "/"

	err = testhelpers.MustBeInvalid(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationErrorCollection)

		if l := len(valErr); l != 1 {
			t.Errorf("Expected %d error, got %s", 1, err)

		}
		if p := valErr.First().Path(); p != "/signature" {
			t.Errorf("Expected path to be %s, got %s", "/signature", p)
		}
	}

	parts[1] = parts[1] + "/"

	err = testhelpers.MustBeInvalid(t, ruleSet.Any(), strings.Join(parts, "."), errors.CodePattern)
	if err != nil {
		valErr := err.(errors.ValidationErrorCollection)

		if l := len(valErr); l != 2 {
			t.Errorf("Expected %d error, got %s", 2, err)
		}
	}

}

func TestVerify(t *testing.T) {
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("Expected err to be nil, got: %s", err)
	}

	ruleSet := josevalidators.NewJWS().WithVerifyJWK(jwk)

	_, verr := ruleSet.Validate(`eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`)

	if verr != nil {
		t.Errorf("Expected validation errors to be ni, got: %s", verr)
	}

}
