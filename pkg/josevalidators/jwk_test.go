package josevalidators_test

import (
	"context"
	"encoding/json"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
	"proto.zip/studio/validate/pkg/testhelpers"
)

// Requirements:
// - Implements JWS rule interface.
func TestJWKRuleSet(t *testing.T) {
	ok := testhelpers.CheckRuleSetInterface[*jose.JWK](josevalidators.JWK())
	if !ok {
		t.Error("Expected rule set to be implemented")
		return
	}
}

// validateJwkTest takes a Json string containing a JWK, parses it, and checks the return value
func testProcessJWK(t testing.TB, jwkJSON string, ruleSet rules.RuleSet[*jose.JWK]) {
	// Attempt to parse the JSON to check its validity
	var jwk map[string]interface{}
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("Failed to parse JWK JSON: %v", err)
	}

	// If the JSON is valid, call the provided function
	if err := ruleSet.Apply(context.Background(), jwk, &jose.JWK{}); err != nil {
		t.Errorf("Apply function returned errors: %v", err)
	}
}

// Requirement
// - Valid ES256 JWK passes validation
func TestES256(t *testing.T) {
	const jwkJson = `{"kty":"EC","crv":"P-256","kid":"EC20240131","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`

	validator := josevalidators.JWK()

	testProcessJWK(t, jwkJson, validator)
}

func TestJWKRuleSet_Required(t *testing.T) {
	rs := josevalidators.JWK()
	if rs.Required() {
		t.Error("default Required() should be false")
	}
}

func TestJWKRuleSet_WithRequired(t *testing.T) {
	rs := josevalidators.JWK().WithRequired()
	if rs == nil {
		t.Fatal("WithRequired returned nil")
	}
	if !rs.Required() {
		t.Error("WithRequired().Required() should be true")
	}
}

func TestJWKRuleSet_Evaluate(t *testing.T) {
	ctx := context.Background()
	// Use a JWK that satisfies validators (kty, use allowed values, etc.)
	jwk, _ := jose.NewJWK(`{"kty":"EC","crv":"P-256","use":"sig","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`)
	err := josevalidators.JWK().Evaluate(ctx, jwk)
	if err != nil {
		t.Errorf("Evaluate: %v", err)
	}
}

func TestJWKRuleSet_WithRule_WithRuleFunc(t *testing.T) {
	rs := josevalidators.JWK().
		WithRuleFunc(func(_ context.Context, _ *jose.JWK) errors.ValidationError {
			return nil
		})
	if rs == nil {
		t.Fatal("WithRuleFunc returned nil")
	}
}

func TestJWKRuleSet_Any(t *testing.T) {
	anySet := josevalidators.JWK().Any()
	if anySet == nil {
		t.Fatal("Any() returned nil")
	}
}

func TestJWKRuleSet_String(t *testing.T) {
	s := josevalidators.JWK().String()
	if s != "JWKRuleSet" {
		t.Errorf("String() = %q", s)
	}
}
