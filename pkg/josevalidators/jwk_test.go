package josevalidators_test

import (
	"encoding/json"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
	"proto.zip/studio/validate/pkg/rules"
	"proto.zip/studio/validate/pkg/testhelpers"
)

// Requirements:
// - Implements JWS rule interface.
func TestJWKRuleSet(t *testing.T) {
	ok := testhelpers.CheckRuleSetInterface[*jose.JWK](josevalidators.NewJWK())
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
	if _, err := ruleSet.Validate(jwk); err != nil {
		t.Errorf("Validate function returned an error: %v", err)
	}
}

// Requirement
// - Valid ES256 JWK passes validation
func TestES256(t *testing.T) {
	const jwkJson = `{"kty":"EC","crv":"P-256","kid":"EC20240131","x":"V-WK2nXgu7A-Qw0Ucc4DRDZihdkw1UdmE1tjnwrItIE","y":"d8353CKrkzkL1RfbOpqpkijnX4GvEaVWt_bcaI3GBys"}`

	validator := josevalidators.NewJWK()

	testProcessJWK(t, jwkJson, validator)
}
