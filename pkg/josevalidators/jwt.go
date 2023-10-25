package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

type JWTRuleSet struct {
	rules.NoConflict[*jose.JWT]
	inner  *JWSRuleSet
	rule   rules.Rule[*jose.JWT]
	parent *JWTRuleSet
}

func NewJWT() *JWTRuleSet {
	return &JWTRuleSet{
		inner: NewJWS(),
	}
}

// Required returns a boolean indicating if the value is allowed to be omitted when included in a nested object.
func (ruleSet *JWTRuleSet) Required() bool {
	return ruleSet.inner.required
}

// WithRequired returns a new rule set with the required flag set.
// Use WithRequired when nesting a RuleSet and the a value is not allowed to be omitted.
func (ruleSet *JWTRuleSet) WithRequired() *JWTRuleSet {
	return &JWTRuleSet{
		inner:  ruleSet.inner.WithRequired(),
		parent: ruleSet,
	}
}

// Validate performs a validation of a RuleSet against a value and returns a JWT value or
// a ValidationErrorCollection.
func (ruleSet *JWTRuleSet) Validate(value any) (*jose.JWT, errors.ValidationErrorCollection) {
	return ruleSet.ValidateWithContext(value, context.Background())
}

// Validate performs a validation of a RuleSet against a value and returns a string value or
// a ValidationErrorCollection.
//
// Also, takes a Context which can be used by rules and error formatting.
func (ruleSet *JWTRuleSet) ValidateWithContext(value any, ctx context.Context) (*jose.JWT, errors.ValidationErrorCollection) {
	jws, err := ruleSet.inner.ValidateWithContext(value, ctx)
	if err != nil {
		return nil, err
	}

	jwt, conversionErr := jose.JWTFromJWS(jws)
	if conversionErr != nil {
		return nil, errors.Collection(
			errors.Errorf(errors.CodeType, ctx, "Unable to convert JWS to JWT"),
		)
	}

	newClaims, err := validate.MapAny().
		WithUnknown().
		WithKey(jose.ExpirationKey, validate.Int64().Any()).
		Validate(jwt.Claims)

	if err != nil {
		return nil, err
	}

	jwt.Claims = newClaims
	return jwt, nil
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationErrorCollection.
func (ruleSet *JWTRuleSet) Evaluate(ctx context.Context, value *jose.JWT) (*jose.JWT, errors.ValidationErrorCollection) {
	return ruleSet.ValidateWithContext(value, ctx)
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWT type.
//
// Use this when implementing custom rules.
func (ruleSet *JWTRuleSet) WithRule(rule rules.Rule[*jose.JWT]) *JWTRuleSet {
	return &JWTRuleSet{
		parent: ruleSet,
		inner:  ruleSet.inner,
		rule:   rule,
	}
}

// WithRuleFunc returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRuleFunc takes an implementation of the Rule interface
// for the jose.JWS type.
//
// Use this when implementing custom rules.
func (v *JWTRuleSet) WithRuleFunc(rule rules.RuleFunc[*jose.JWT]) *JWTRuleSet {
	return v.WithRule(rule)
}

// Any returns a new RuleSet that wraps the domain RuleSet in any Any rule set
// which can then be used in nested validation.
func (ruleSet *JWTRuleSet) Any() rules.RuleSet[any] {
	return rules.WrapAny[*jose.JWT](ruleSet)
}

// String returns a string representation of the rule set suitable for debugging.
func (ruleSet *JWTRuleSet) String() string {
	return ruleSet.inner.String()
}
