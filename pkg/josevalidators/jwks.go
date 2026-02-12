package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

// JWKSRuleSet validates a JSON Web Key Set (keys array of JWKs).
type JWKSRuleSet struct {
	rules.NoConflict[*jose.JWKS]
	inner *rules.ObjectRuleSet[*jose.JWKS, string, any]
	items *JWKRuleSet
}

var baseJwksRuleSet *rules.ObjectRuleSet[*jose.JWKS, string, any] = rules.Struct[*jose.JWKS]()

// NewJWKS creates a new jose.JWKS RuleSet.
func NewJWKS() *JWKSRuleSet {
	return &JWKSRuleSet{
		items: JWK(),
		inner: baseJwksRuleSet,
	}
}

// Required returns a boolean indicating if the value is allowed to be omitted when included in a nested object.
func (ruleSet *JWKSRuleSet) Required() bool {
	return ruleSet.inner.Required()
}

// WithRequired returns a new rule set with the required flag set.
// Use WithRequired when nesting a RuleSet and the a value is not allowed to be omitted.
func (ruleSet *JWKSRuleSet) WithRequired() *JWKSRuleSet {
	return &JWKSRuleSet{
		inner: ruleSet.inner.WithRequired(),
	}
}

// Apply performs a validation of a RuleSet against a value and returns a string value or
// a ValidationError.
func (ruleSet *JWKSRuleSet) Apply(ctx context.Context, input, output any) errors.ValidationError {
	return ruleSet.inner.
		WithKey("keys", rules.Slice[*jose.JWK]().WithItemRuleSet(ruleSet.items).Any()).
		Apply(ctx, input, output)
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationError.
func (ruleSet *JWKSRuleSet) Evaluate(ctx context.Context, value *jose.JWKS) errors.ValidationError {
	return ruleSet.inner.
		WithKey("keys", rules.Slice[*jose.JWK]().WithItemRuleSet(ruleSet.items).Any()).
		Evaluate(ctx, value)
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWKS type.
//
// Use this when implementing custom rules.
func (ruleSet *JWKSRuleSet) WithRule(rule rules.Rule[*jose.JWKS]) *JWKSRuleSet {
	return &JWKSRuleSet{
		inner: ruleSet.inner.WithRule(rule),
	}
}

// WithRuleFunc returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRuleFunc takes an implementation of the Rule interface
// for the jose.JWKS type.
//
// Use this when implementing custom rules.
func (v *JWKSRuleSet) WithRuleFunc(rule rules.RuleFunc[*jose.JWKS]) *JWKSRuleSet {
	return v.WithRule(rule)
}

// Any returns a new RuleSet that wraps the domain RuleSet in any Any rule set
// which can then be used in nested validation.
func (ruleSet *JWKSRuleSet) Any() rules.RuleSet[any] {
	return rules.WrapAny[*jose.JWKS](ruleSet)
}

// String returns a string representation of the rule set suitable for debugging.
func (ruleSet *JWKSRuleSet) String() string {
	return ""
}
