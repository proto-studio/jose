package josevalidators_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

func TestBug(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9kZW1vLmNlcnRpZmljYXRpb24ub3BlbmlkLm5ldC90ZXN0L1N3Nm1VdU0xa3BEU205dC9jYWxsYmFjayIsInN0YXRlIjoiREFRVnF6b2hLbyIsIm5vbmNlIjoiOVBwaXFiZlR0eCIsImNsaWVudF9pZCI6Ijc0ZTYyYWZlLWUyYTctNDRiMS1iZTlkLTRkOTUwMWIyNWMzMSJ9."

	jwt, err := josevalidators.JWT().Apply(context.Background(), jwtStr)
	if err != nil {
		t.Error("Unexpected validation error:", err)
	}
	if jwt == nil {
		t.Error("Expect JWT to not be nil")
	}
}

func TestJWTOutputTypes(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9."

	t.Run("Apply returns *jose.JWT", func(t *testing.T) {
		jwt, err := josevalidators.JWT().Apply(context.Background(), jwtStr)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if jwt == nil {
			t.Error("Expected JWT to not be nil")
		}
		if jwt.Claims == nil {
			t.Error("Expected JWT claims to not be nil")
		}
	})
}

func TestJWTRuleSet_Required(t *testing.T) {
	rs := josevalidators.JWT()
	if rs.Required() {
		t.Error("default Required() should be false")
	}
}

func TestJWTRuleSet_WithRequired(t *testing.T) {
	rs := josevalidators.JWT().WithRequired()
	if rs == nil {
		t.Fatal("WithRequired returned nil")
	}
	if !rs.Required() {
		t.Error("WithRequired().Required() should be true")
	}
}

func TestJWTRuleSet_WithRule_WithRuleFunc(t *testing.T) {
	rs := josevalidators.JWT().
		WithRuleFunc(func(_ context.Context, _ *jose.JWT) errors.ValidationError {
			return nil
		})
	if rs == nil {
		t.Fatal("WithRuleFunc returned nil")
	}
}

func TestJWTRuleSet_WithClaim(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()

	t.Run("valid claim passes", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIn0."
		rs := josevalidators.JWT().WithClaim(jose.SubjectKey, rules.String().Any())
		jwt, err := rs.Apply(ctx, compact)
		if err != nil {
			t.Errorf("WithClaim(sub string): %v", err)
		}
		if jwt == nil || jwt.Claims[jose.SubjectKey] != "user123" {
			t.Errorf("expected sub=user123, got %v", jwt)
		}
	})

	t.Run("required claim missing fails", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJhdWQiOiJteS1hdWRpZW5jZSJ9."
		rs := josevalidators.JWT().WithClaim(jose.SubjectKey, rules.String().WithRequired().Any())
		_, err := rs.Apply(ctx, compact)
		if err == nil {
			t.Error("WithClaim(sub required) with missing sub should error")
		}
	})

	t.Run("multiple claims", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ."
		rs := josevalidators.JWT().
			WithClaim(jose.SubjectKey, rules.String().Any()).
			WithClaim(jose.IssuerKey, rules.String().Any())
		jwt, err := rs.Apply(ctx, compact)
		if err != nil {
			t.Errorf("WithClaim(sub + iss): %v", err)
		}
		if jwt.Claims[jose.SubjectKey] != "alice" || jwt.Claims[jose.IssuerKey] != "https://example.com" {
			t.Errorf("expected sub=alice iss=https://example.com, got %v", jwt.Claims)
		}
	})

	t.Run("iss claim valid passes", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL215LWF1dGguc2VydmljZS9pZCJ9."
		rs := josevalidators.JWT().WithClaim(jose.IssuerKey, rules.String().WithRequired().Any())
		jwt, err := rs.Apply(ctx, compact)
		if err != nil {
			t.Errorf("WithClaim(iss required): %v", err)
		}
		if jwt == nil {
			t.Fatal("expected jwt non-nil")
		}
		if got := jwt.Claims[jose.IssuerKey]; got != "https://my-auth.service/id" {
			t.Errorf("expected iss=https://my-auth.service/id, got %v", got)
		}
	})

	t.Run("iss claim missing fails when required", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0."
		rs := josevalidators.JWT().WithClaim(jose.IssuerKey, rules.String().WithRequired().Any())
		_, err := rs.Apply(ctx, compact)
		if err == nil {
			t.Error("WithClaim(iss required) with missing iss should error")
		}
	})

	t.Run("iss claim allowed values", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2V4cGVjdGVkLmlzc3Vlci9pZCJ9."
		rs := josevalidators.JWT().WithClaim(jose.IssuerKey,
			rules.String().WithAllowedValues("https://expected.issuer/id").Any())
		jwt, err := rs.Apply(ctx, compact)
		if err != nil {
			t.Errorf("WithClaim(iss allowed): %v", err)
		}
		if jwt.Claims[jose.IssuerKey] != "https://expected.issuer/id" {
			t.Errorf("expected iss=https://expected.issuer/id, got %v", jwt.Claims[jose.IssuerKey])
		}
	})

	t.Run("iss claim wrong value fails allowed values", func(t *testing.T) {
		compact := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL3dyb25nLmlzc3Vlci9pZCJ9."
		rs := josevalidators.JWT().WithClaim(jose.IssuerKey,
			rules.String().WithAllowedValues("https://expected.issuer/id").Any())
		_, err := rs.Apply(ctx, compact)
		if err == nil {
			t.Error("WithClaim(iss allowed values) with wrong iss should error")
		}
	})

	t.Run("claim rules run when Evaluate called directly", func(t *testing.T) {
		// Build JWT without Apply, then Evaluate with WithClaim rule — claim rules must run.
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.SubjectKey: "ok"}
		rs := josevalidators.JWT().WithClaim(jose.SubjectKey, rules.String().WithRequired().Any())
		err := rs.Evaluate(ctx, jwt)
		if err != nil {
			t.Errorf("Evaluate with valid sub claim should pass: %v", err)
		}
		// applyClaimRules runs in evaluate(), so claim value is written back (e.g. normalized)
		if jwt.Claims[jose.SubjectKey] != "ok" {
			t.Errorf("expected sub=ok after Evaluate, got %v", jwt.Claims[jose.SubjectKey])
		}
	})

	t.Run("Evaluate directly with missing required claim fails", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{} // no sub
		rs := josevalidators.JWT().WithClaim(jose.SubjectKey, rules.String().WithRequired().Any())
		err := rs.Evaluate(ctx, jwt)
		if err == nil {
			t.Error("Evaluate with missing required sub should error")
		}
	})

	t.Run("multiple claim errors are joined", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{} // missing both sub and iss
		rs := josevalidators.JWT().
			WithClaim(jose.SubjectKey, rules.String().WithRequired().Any()).
			WithClaim(jose.IssuerKey, rules.String().WithRequired().Any())
		err := rs.Evaluate(ctx, jwt)
		if err == nil {
			t.Fatal("Evaluate with two missing required claims should error")
		}
		// errors.Join returns an error that unwraps to []error
		unwrap, ok := err.(interface{ Unwrap() []error })
		if !ok {
			t.Skip("error does not implement Unwrap() []error")
		}
		subErrs := unwrap.Unwrap()
		if len(subErrs) < 2 {
			t.Errorf("expected at least 2 joined errors, got %d", len(subErrs))
		}
	})

	t.Run("two rules for same claim both run (cumulative)", func(t *testing.T) {
		// Two WithClaim("sub", ...) rules: both run in order, second receives first's output.
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.SubjectKey: "  alice  "}
		rs := josevalidators.JWT().
			WithClaim(jose.SubjectKey, rules.String().Any()). // allow and pass through
			WithClaim(jose.SubjectKey, rules.String().WithRequired().Any())
		err := rs.Evaluate(ctx, jwt)
		if err != nil {
			t.Errorf("two rules for same claim should both run and pass: %v", err)
		}
		// First rule runs: "  alice  " -> "  alice  "; second runs on that value (required passes)
		if jwt.Claims[jose.SubjectKey] != "  alice  " {
			t.Errorf("expected sub unchanged after two rules, got %q", jwt.Claims[jose.SubjectKey])
		}
	})
}

func TestJWTRuleSet_Any(t *testing.T) {
	anySet := josevalidators.JWT().Any()
	if anySet == nil {
		t.Fatal("Any() returned nil")
	}
}

func TestJWTRuleSet_String(t *testing.T) {
	// Base rule set
	if s := josevalidators.JWT().String(); s != "JWTRuleSet" {
		t.Errorf("JWT().String() = %q, want JWTRuleSet", s)
	}
	// WithRequired, WithTime, WithClaim, WithJWK, WithJWKS show in chain
	rs := josevalidators.JWT().WithRequired()
	if s := rs.String(); s != "JWTRuleSet.WithRequired()" {
		t.Errorf("JWT().WithRequired().String() = %q, want JWTRuleSet.WithRequired()", s)
	}
	rs = josevalidators.JWT().WithTime(time.Unix(0, 0))
	if s := rs.String(); s != "JWTRuleSet.WithTime()" {
		t.Errorf("JWT().WithTime().String() = %q, want JWTRuleSet.WithTime()", s)
	}
	rs = josevalidators.JWT().WithClaim(jose.SubjectKey, rules.String().Any())
	if s := rs.String(); s != "JWTRuleSet.WithClaim(sub)" {
		t.Errorf("JWT().WithClaim(sub,...).String() = %q, want JWTRuleSet.WithClaim(sub)", s)
	}
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"x","n":"n","e":"AQAB"}`)
	rs = josevalidators.JWT().WithJWK(jwk)
	if s := rs.String(); s != "JWTRuleSet.WithJWK()" {
		t.Errorf("JWT().WithJWK().String() = %q, want JWTRuleSet.WithJWK()", s)
	}
	jwks := jose.NewJWKS(jwk)
	rs = josevalidators.JWT().WithJWKS(jwks)
	if s := rs.String(); s != "JWTRuleSet.WithJWKS()" {
		t.Errorf("JWT().WithJWKS().String() = %q, want JWTRuleSet.WithJWKS()", s)
	}
	rs = josevalidators.JWT().WithJWKSURL("https://example.com/keys")
	if s := rs.String(); s != "JWTRuleSet.WithJWKSURL(...)" {
		t.Errorf("JWT().WithJWKSURL().String() = %q, want JWTRuleSet.WithJWKSURL(...)", s)
	}
	// Chained methods
	rs = josevalidators.JWT().WithRequired().WithClaim(jose.IssuerKey, rules.String().Any())
	if s := rs.String(); s != "JWTRuleSet.WithRequired().WithClaim(iss)" {
		t.Errorf("chained String() = %q, want JWTRuleSet.WithRequired().WithClaim(iss)", s)
	}
}

func TestJWT_WithVerifyJWK(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	// Token has exp=1708281011; use WithTime so it is not considered expired
	ruleSet := josevalidators.JWT().WithTime(time.Unix(1708281000, 0)).WithVerifyJWK(jwk)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	jwt, err := ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Errorf("JWT WithVerifyJWK Apply: %v", err)
	}
	if jwt == nil {
		t.Error("expected JWT to be set")
	}
}

func TestJWT_WithVerifyFunc(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	// Token has exp=1708281011; use WithTime so it is not considered expired
	ruleSet := josevalidators.JWT().WithTime(time.Unix(1708281000, 0)).WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return jwk })
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	_, err := ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Errorf("JWT WithVerifyFunc Apply: %v", err)
	}
}

func TestJWT_WithJWKS(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := jose.NewJWKS(jwk)
	ruleSet := josevalidators.JWT().WithTime(time.Unix(1708281000, 0)).WithJWKS(jwks)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	jwt, err := ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Errorf("JWT WithJWKS Apply: %v", err)
	}
	if jwt == nil {
		t.Error("expected JWT to be set")
	}
}

func TestJWT_ExpNbf(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()

	t.Run("exp in past fails without WithTime", func(t *testing.T) {
		// Token expired at Unix 1 (1970)
		payload := base64url.Encode([]byte(`{"exp":1,"sub":"a"}`))
		compact := "eyJhbGciOiJub25lIn0." + payload + "."
		_, err := josevalidators.JWT().Apply(ctx, compact)
		if err == nil {
			t.Error("Apply with exp in past should error")
		}
	})

	t.Run("nbf in future fails without WithTime", func(t *testing.T) {
		// Token not valid until far future
		payload := base64url.Encode([]byte(`{"nbf":9999999999,"sub":"a"}`))
		compact := "eyJhbGciOiJub25lIn0." + payload + "."
		_, err := josevalidators.JWT().Apply(ctx, compact)
		if err == nil {
			t.Error("Apply with nbf in future should error")
		}
	})

	t.Run("exp in future and nbf in past pass without WithTime", func(t *testing.T) {
		now := time.Now().Unix()
		exp := now + 3600
		nbf := now - 3600
		payload := base64url.Encode([]byte(fmt.Sprintf(`{"exp":%d,"nbf":%d,"sub":"a"}`, exp, nbf)))
		compact := "eyJhbGciOiJub25lIn0." + payload + "."
		_, err := josevalidators.JWT().Apply(ctx, compact)
		if err != nil {
			t.Errorf("Apply with valid exp/nbf window should pass: %v", err)
		}
	})
}

func TestJWT_WithTime(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()

	// Fixed evaluation time: 1500000000 (mid-2017)
	eval := time.Unix(1500000000, 0)
	expInFuture := int64(1500003600) // eval + 1h
	expInPast := int64(1500000000 - 3600)
	nbfInPast := int64(1500000000 - 3600)
	nbfInFuture := int64(1500003600)

	t.Run("WithTime: exp after eval passes", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.ExpirationKey: expInFuture, jose.SubjectKey: "a"}
		rs := josevalidators.JWT().WithTime(eval)
		err := rs.Evaluate(ctx, jwt)
		if err != nil {
			t.Errorf("WithTime: exp after eval should pass: %v", err)
		}
	})

	t.Run("WithTime: exp before eval fails", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.ExpirationKey: expInPast, jose.SubjectKey: "a"}
		rs := josevalidators.JWT().WithTime(eval)
		err := rs.Evaluate(ctx, jwt)
		if err == nil {
			t.Error("WithTime: exp before eval should error")
		}
	})

	t.Run("WithTime: nbf before eval passes", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.NotBeforeKey: nbfInPast, jose.SubjectKey: "a"}
		rs := josevalidators.JWT().WithTime(eval)
		err := rs.Evaluate(ctx, jwt)
		if err != nil {
			t.Errorf("WithTime: nbf before eval should pass: %v", err)
		}
	})

	t.Run("WithTime: nbf after eval fails", func(t *testing.T) {
		jwt := jose.NewJWT(nil)
		jwt.Claims = jose.Claims{jose.NotBeforeKey: nbfInFuture, jose.SubjectKey: "a"}
		rs := josevalidators.JWT().WithTime(eval)
		err := rs.Evaluate(ctx, jwt)
		if err == nil {
			t.Error("WithTime: nbf after eval should error")
		}
	})

	t.Run("WithTime: Apply with fixed time accepts token valid at that time", func(t *testing.T) {
		payload := base64url.Encode([]byte(`{"exp":1500003600,"nbf":1499996400,"sub":"a"}`))
		compact := "eyJhbGciOiJub25lIn0." + payload + "."
		rs := josevalidators.JWT().WithTime(eval)
		jwt, err := rs.Apply(ctx, compact)
		if err != nil {
			t.Errorf("WithTime Apply: %v", err)
		}
		if jwt == nil || jwt.Claims[jose.SubjectKey] != "a" {
			t.Errorf("expected jwt with sub=a, got %v", jwt)
		}
	})

	t.Run("WithTime: Apply with fixed time rejects expired token", func(t *testing.T) {
		// exp=1499990000 is before eval=1500000000
		payload := base64url.Encode([]byte(`{"exp":1499990000,"sub":"a"}`))
		compact := "eyJhbGciOiJub25lIn0." + payload + "."
		rs := josevalidators.JWT().WithTime(eval)
		_, err := rs.Apply(ctx, compact)
		if err == nil {
			t.Error("WithTime Apply with expired token should error")
		}
	})
}

// Test JWT.Evaluate(ctx, jwt) so evaluate(ctx, jwt, nil) is used (value.JWS() path).
func TestJWTRuleSet_Evaluate_WithParsedJWT(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
	jwt, err := josevalidators.JWT().Apply(ctx, compact)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	err = josevalidators.JWT().Evaluate(ctx, jwt)
	if err != nil {
		t.Errorf("Evaluate(parsed jwt): %v", err)
	}
}

// Apply returns (*jose.JWT, error); no output pointer, so "wrong output type" no longer applies.

// evaluate(ctx, jwt, nil) when value.JWS() fails (e.g. unmarshalable claims)
func TestJWTRuleSet_Evaluate_JWSFails(t *testing.T) {
	ctx := context.Background()
	jwt := jose.NewJWT(nil)
	jwt.Claims["x"] = make(chan int) // cannot JSON marshal
	err := josevalidators.JWT().Evaluate(ctx, jwt)
	if err == nil {
		t.Fatal("Evaluate when JWS() fails should error")
	}
}

// evaluate: rule in chain returns error
func TestJWTRuleSet_Evaluate_RuleReturnsError(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.e30"
	jwt, err := josevalidators.JWT().Apply(ctx, compact)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	failRule := josevalidators.JWT().WithRuleFunc(func(_ context.Context, _ *jose.JWT) errors.ValidationError {
		return errors.Errorf(errors.CodeInternal, context.Background(), "fail", "fail")
	})
	err = failRule.Evaluate(ctx, jwt)
	if err == nil {
		t.Fatal("Evaluate when rule returns error should error")
	}
}

// evaluate: rule in chain returns nil (success) so we hit the full loop and return nil.
func TestJWTRuleSet_Evaluate_RuleSucceeds(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	compact := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.e30"
	jwt, err := josevalidators.JWT().Apply(ctx, compact)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	passRule := josevalidators.JWT().WithRuleFunc(func(_ context.Context, _ *jose.JWT) errors.ValidationError {
		return nil
	})
	err = passRule.Evaluate(ctx, jwt)
	if err != nil {
		t.Errorf("Evaluate when rule returns nil should succeed: %v", err)
	}
}

func TestJWT_Apply_JWTFromJWSError(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	// Valid header, payload that is base64 but not valid JSON → JWTFromJWS fails
	payloadB64 := base64url.Encode([]byte("not-json"))
	compact := "eyJhbGciOiJub25lIn0." + payloadB64 + ".e30"
	_, err := josevalidators.JWT().Apply(ctx, compact)
	if err == nil {
		t.Fatal("Apply when JWTFromJWS fails (invalid payload JSON) should error")
	}
}

func TestJWT_Apply_ClaimsValidationError(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	// exp as string instead of int → claims Apply fails
	payload := base64url.Encode([]byte(`{"exp":"not-a-number"}`))
	compact := "eyJhbGciOiJub25lIn0." + payload + ".e30"
	_, err := josevalidators.JWT().Apply(ctx, compact)
	if err == nil {
		t.Fatal("Apply when claims validation fails should error")
	}
}

