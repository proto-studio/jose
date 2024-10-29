package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

type JWKRuleSet struct {
	rules.NoConflict[*jose.JWK]
	inner *rules.ObjectRuleSet[*jose.JWK, string, any]
}

var baseJwkRuleSet *rules.ObjectRuleSet[*jose.JWK, string, any] = rules.Struct[*jose.JWK]().
	WithKey("alg", rules.String().Any()).
	// Technically other values are allowed for "use" but we're omitting them. Submit a pull request if you find a valid use other than "sig" and "enc"
	WithKey("use", rules.String().WithAllowedValues("sig", "enc").Any()).
	WithKey("kty", rules.String().Any()).
	WithKey("crv", rules.String().WithAllowedValues("P-256", "P-384", "P-521").Any()).
	WithKey("kid", rules.String().Any()).
	WithKey("x", rules.String().Any()).
	WithKey("y", rules.String().Any()).
	WithKey("d", rules.String().Any()).
	WithKey("n", rules.String().Any()).
	WithKey("e", rules.String().Any())

// JWK creates a new jose.JWK RuleSet.
func JWK() *JWKRuleSet {
	return &JWKRuleSet{
		inner: baseJwkRuleSet,
	}
}

// Required returns a boolean indicating if the value is allowed to be omitted when included in a nested object.
func (ruleSet *JWKRuleSet) Required() bool {
	return ruleSet.inner.Required()
}

// WithRequired returns a new rule set with the required flag set.
// Use WithRequired when nesting a RuleSet and the a value is not allowed to be omitted.
func (ruleSet *JWKRuleSet) WithRequired() *JWKRuleSet {
	return &JWKRuleSet{
		inner: ruleSet.inner.WithRequired(),
	}
}

// Apply performs a validation of a RuleSet against a value and returns a ValidationErrorCollection.
func (ruleSet *JWKRuleSet) Apply(ctx context.Context, input, output any) errors.ValidationErrorCollection {
	return ruleSet.inner.Apply(ctx, input, output)
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationErrorCollection.
func (ruleSet *JWKRuleSet) Evaluate(ctx context.Context, value *jose.JWK) errors.ValidationErrorCollection {
	return ruleSet.inner.Evaluate(ctx, value)
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWK type.
//
// Use this when implementing custom rules.
func (ruleSet *JWKRuleSet) WithRule(rule rules.Rule[*jose.JWK]) *JWKRuleSet {
	return &JWKRuleSet{
		inner: ruleSet.inner.WithRule(rule),
	}
}

// WithRuleFunc returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRuleFunc takes an implementation of the Rule interface
// for the jose.JWK type.
//
// Use this when implementing custom rules.
func (v *JWKRuleSet) WithRuleFunc(rule rules.RuleFunc[*jose.JWK]) *JWKRuleSet {
	return v.WithRule(rule)
}

// Any returns a new RuleSet that wraps the domain RuleSet in any Any rule set
// which can then be used in nested validation.
func (ruleSet *JWKRuleSet) Any() rules.RuleSet[any] {
	return rules.WrapAny[*jose.JWK](ruleSet.inner)
}

// String returns a string representation of the rule set suitable for debugging.
func (ruleSet *JWKRuleSet) String() string {
	return "JWKRuleSet"
}
