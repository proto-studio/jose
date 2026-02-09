package josevalidators_test

import (
	"context"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/errors"
)

func TestBug(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9kZW1vLmNlcnRpZmljYXRpb24ub3BlbmlkLm5ldC90ZXN0L1N3Nm1VdU0xa3BEU205dC9jYWxsYmFjayIsInN0YXRlIjoiREFRVnF6b2hLbyIsIm5vbmNlIjoiOVBwaXFiZlR0eCIsImNsaWVudF9pZCI6Ijc0ZTYyYWZlLWUyYTctNDRiMS1iZTlkLTRkOTUwMWIyNWMzMSJ9."

	var jwt *jose.JWT
	err := josevalidators.JWT().Apply(context.Background(), jwtStr, &jwt)

	if jwt == nil {
		t.Error("Expect JWT to not be nil")
	}

	if err != nil {
		t.Error("Unexpected validation error:", err)
	}
}

func TestJWTOutputTypes(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9."

	t.Run("any output", func(t *testing.T) {
		var output any
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
	})

	t.Run("*jose.JWT output", func(t *testing.T) {
		var output jose.JWT
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output.Claims == nil {
			t.Error("Expected JWT claims to not be nil")
		}
	})

	t.Run("**jose.JWT output", func(t *testing.T) {
		var output *jose.JWT
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
		if output.Claims == nil {
			t.Error("Expected JWT claims to not be nil")
		}
	})

	t.Run("jose.JWS output", func(t *testing.T) {
		var output jose.JWS
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output.Payload == "" {
			t.Error("Expected JWS payload to not be empty")
		}
	})

	t.Run("*jose.JWS output", func(t *testing.T) {
		var output *jose.JWS
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
		if output.Payload == "" {
			t.Error("Expected JWS payload to not be empty")
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

func TestJWTRuleSet_Any(t *testing.T) {
	anySet := josevalidators.JWT().Any()
	if anySet == nil {
		t.Fatal("Any() returned nil")
	}
}

func TestJWTRuleSet_String(t *testing.T) {
	s := josevalidators.JWT().String()
	if s != "JWSRuleSet" {
		t.Errorf("String() = %q", s)
	}
}

func TestJWT_WithVerifyJWK(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	ruleSet := josevalidators.JWT().WithVerifyJWK(jwk)
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	var jwt *jose.JWT
	err := ruleSet.Apply(context.Background(), compact, &jwt)
	if err != nil {
		t.Errorf("JWT WithVerifyJWK Apply: %v", err)
	}
	if jwt == nil {
		t.Error("expected JWT to be set")
	}
}

func TestJWT_WithVerifyFunc(t *testing.T) {
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	ruleSet := josevalidators.JWT().WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return jwk })
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	var jwt *jose.JWT
	err := ruleSet.Apply(context.Background(), compact, &jwt)
	if err != nil {
		t.Errorf("JWT WithVerifyFunc Apply: %v", err)
	}
}

