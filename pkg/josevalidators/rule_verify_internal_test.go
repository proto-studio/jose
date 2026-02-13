// Package josevalidators (not _test) to access unexported verifyRule for coverage.
package josevalidators

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

type otherJWSRule struct{}

func (otherJWSRule) Evaluate(context.Context, *jose.JWS) errors.ValidationError {
	return nil
}

func (otherJWSRule) Replaces(r rules.Rule[*jose.JWS]) bool {
	return false
}

func (otherJWSRule) String() string {
	return "other"
}

// TestVerifyRule_Replaces tests that verifyRule.Replaces returns true for another verifyRule.
func TestVerifyRule_Replaces(t *testing.T) {
	r := &verifyRule{fn: func(context.Context, jose.Header) *jose.JWK { return nil }}
	if !r.Replaces(r) {
		t.Error("Replaces(self) should be true")
	}
	var other otherJWSRule
	if r.Replaces(&other) {
		t.Error("Replaces(different rule type) should be false")
	}
}

// TestVerifyRule_String tests that verifyRule.String returns a fixed label.
func TestVerifyRule_String(t *testing.T) {
	// Rule's String() is used when added via WithRule; built-ins use RuleSet label (WithJWK(), etc.)
	r := &verifyRule{fn: nil}
	if s := r.String(); s != "WithVerifyFunc(...)" {
		t.Errorf("String() = %q, want WithVerifyFunc(...)", s)
	}
}

// TestJWS_WithJWKSURL_CacheShared tests that the JWKS URL cache is shared across validators.
func TestJWS_WithJWKSURL_CacheShared(t *testing.T) {
	clearJWKSCacheForTest()
	defer clearJWKSCacheForTest()

	var requestCount atomic.Int32
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwks := jose.NewJWKS(jwk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks.String()))
	}))
	defer server.Close()

	url := server.URL
	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`

	// Two separate validators using the same JWKS URL
	ruleSet1 := JWS().WithJWKSURL(url)
	ruleSet2 := JWS().WithJWKSURL(url)

	ctx := context.Background()
	out1, err := ruleSet1.Apply(ctx, compact)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	out2, err := ruleSet2.Apply(ctx, compact)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	_, _ = out1, out2

	if n := requestCount.Load(); n != 1 {
		t.Errorf("expected 1 request (cache shared), got %d", n)
	}
}

// TestJWS_WithJWKSURL_304NotModified tests that a 304 response reuses the cached JWKS.
func TestJWS_WithJWKSURL_304NotModified(t *testing.T) {
	clearJWKSCacheForTest()
	defer clearJWKSCacheForTest()

	const testETag = `"abc123"`
	var requestCount atomic.Int32
	jwk, err := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwks := jose.NewJWKS(jwk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if strings.Trim(r.Header.Get("If-None-Match"), `"`) == strings.Trim(testETag, `"`) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", testETag)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks.String()))
	}))
	defer server.Close()

	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	ruleSet := JWS().WithJWKSURL(server.URL)

	// First request: full 200
	_, err = ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("after first Apply: expected 1 request, got %d", requestCount.Load())
	}

	// Wait past min TTL so we revalidate
	time.Sleep(minJWKSCacheTTL + 50*time.Millisecond)

	// Second request: conditional, server returns 304
	var out2 *jose.JWS
	out2, err = ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if n := requestCount.Load(); n != 2 {
		t.Errorf("after second Apply: expected 2 requests (conditional), got %d", n)
	}
	if out2 == nil || out2.Payload == "" {
		t.Error("expected JWS after 304 to use cached value")
	}
}


// TestJWS_WithJWKSURL_MinTTL tests that the JWKS cache enforces a minimum TTL before revalidation.
func TestJWS_WithJWKSURL_MinTTL(t *testing.T) {
	clearJWKSCacheForTest()
	defer clearJWKSCacheForTest()

	var requestCount atomic.Int32
	jwk, _ := jose.NewJWK(`{"kty":"RSA","kid":"RSA20240212","n":"y4hxdh_gsACZsZpUg-l4hpdf5Qo4lUyJV1SbJRsJuqRLKTZHYhrTJ1uUDfIYNcNeemxL73zytN6SfJvBgDYThqN2OTrX_G1LMadI_CtKrV-kUZXjyY41KAcgHvPuVhhWX3ksYaKqVijT7ViOS3DG3t7AKVsD_BBIzxQ_ZaQLKG5YmG64xL6WGNdpTrBeT87-ZJ9-ojhhP2eytkjLhB6aO5kzIiXRsN_b0A0ubm2ujKkBP4tnsGGcbJzwlappWJb3qdOYXL77kcFIuxIRsfKCrb5Tuds862jpawKYZdFC_46tJ_CRieHMo-o-6XGmfp_VXvAv2FkRDbqDtnU8_mKvuQ","e":"AQAB"}`)
	jwks := jose.NewJWKS(jwk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks.String()))
	}))
	defer server.Close()

	compact := `eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTQTIwMjQwMjEyIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhZmQyODE0Yi00M2I4LTRjYmYtOGFmYy03NDY2MDJlMDBjMDQiLCJhdXRoX3RpbWUiOjE3MDgyNzczMzUsImV4cCI6MTcwODI4MTAxMSwiaWF0IjoxNzA4Mjc3NDEwLCJpc3MiOiJodHRwczovL3N0dWRpby5kZXYucHJvdG9hdXRoLmNvbSIsIm5vbmNlIjoiRjFGRnh5Y1lrWSIsInN1YiI6IjJjYjZiNmQ2LWEwY2ItNGI3Mi1iY2EwLTI1YTI5NzJkNjM3YiJ9.Q3Coybou0LIyQAhKDWSlq92E5xAIBfiOm51feugylkZ4SV5MQIwRJLNkK7ucYPUzMROZ6E5xFIlrbVojo4vPM8CTODD7A9IOKwa-qaEikIx7K4MGLCHo-NLGdMEEQh8hQZ_4Bs8tlJUSOn_SUXeSNXTyUI7jpRZ0cKtcyS9V-QIhe1hNcm9_RCJ2auOqr9ZyDWUelpdLGoaN1oT9aAsFUAfUjlA0E_V8J5IV2BLZ96W21ENfB4Jiys0NFiM-FNk-M94Xmq9KK51Brd-zmDBYQ3Sw7_8dy_PtLPLGbM9geDcTsi_RjjjQak2p5iR6qt2xiicQQhlJdYCVDRBIdXbhcg`
	ruleSet := JWS().WithJWKSURL(server.URL)

	// First request
	_, err := ruleSet.Apply(context.Background(), compact)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("after first Apply: expected 1 request, got %d", requestCount.Load())
	}

	// Immediate second request: must use cache (min TTL), no new request
	if _, err := ruleSet.Apply(context.Background(), compact); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if n := requestCount.Load(); n != 1 {
		t.Errorf("expected 1 request (min TTL prevents refetch), got %d", n)
	}
}
