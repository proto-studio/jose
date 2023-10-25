package josevalidators_test

import (
	"encoding/json"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/rules"
	"proto.zip/studio/validate/pkg/testhelpers"
)

// validateJwkTest takes a Json string containing a JWK, parses it, and checks the return value
func testProcessJWKS(t testing.TB, jwksJSON string, ruleSet rules.RuleSet[*jose.JWKS]) {
	// Attempt to parse the JSON to check its validity
	var jwks map[string]any
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// If the JSON is valid, call the provided function
	// Purposely converting to Any() here because that will be the most common use of this rule set.
	if _, err := ruleSet.Any().Validate(jwks); err != nil {
		t.Errorf("Validate function returned an error: %v", err)
	}
}

// Requirements:
// - Implements JWKS rule interface.
func TestJWKSRuleSet(t *testing.T) {
	ok := testhelpers.CheckRuleSetInterface[*jose.JWK](josevalidators.NewJWK())
	if !ok {
		t.Error("Expected rule set to be implemented")
		return
	}
}

// Requirements:
// - Properly formatted JWKS passes
func TestJWKSBasic(t *testing.T) {
	const jwksJSON = `{"keys":[{"kty":"EC","crv":"P-256","kid":"EC20240131","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}]}`
	ruleSet := josevalidators.NewJWKS()
	testProcessJWKS(t, jwksJSON, ruleSet)
}
