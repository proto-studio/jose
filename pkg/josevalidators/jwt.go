package josevalidators

import (
	"context"
	"reflect"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

type JWTRuleSet struct {
	rules.NoConflict[*jose.JWT]
	inner  *JWSRuleSet
	rule   rules.Rule[*jose.JWT]
	parent *JWTRuleSet
}

func JWT() *JWTRuleSet {
	return &JWTRuleSet{
		inner: JWS(),
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

// Apply performs a validation of a RuleSet against a value and returns a JWT value or
// a ValidationError.
func (ruleSet *JWTRuleSet) Apply(ctx context.Context, input, output any) errors.ValidationError {
	var jws *jose.JWS
	if err := ruleSet.inner.Apply(ctx, input, &jws); err != nil {
		return err
	}

	jwt, conversionErr := jose.JWTFromJWS(jws)
	if conversionErr != nil {
		return errors.Errorf(errors.CodeType, ctx, "Unable to convert JWS to JWT", "Unable to convert JWS to JWT")
	}

	var newClaims map[string]any
	if err := rules.StringMap[any]().
		WithUnknown().
		WithKey(jose.ExpirationKey, rules.Int64().Any()).
		Apply(ctx, jwt.Claims, &newClaims); err != nil {
		return err
	}

	jwt.Claims = newClaims

	outputVal := reflect.ValueOf(output)
	outputElem := outputVal.Elem()

	if outputElem.Kind() == reflect.Interface && outputElem.IsNil() {
		outputElem.Set(reflect.ValueOf(jwt))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(jwt)) {
		outputElem.Set(reflect.ValueOf(jwt))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(*jwt)) {
		outputElem.Set(reflect.ValueOf(*jwt))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(jws)) {
		outputElem.Set(reflect.ValueOf(jws))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(*jws)) {
		outputElem.Set(reflect.ValueOf(*jws))
	} else {
		return errors.Errorf(
			errors.CodeInternal, ctx, "Cannot assign", "Cannot assign %T to %T", jwt, outputElem.Interface(),
		)
	}

	return nil
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationError.
func (ruleSet *JWTRuleSet) Evaluate(ctx context.Context, value *jose.JWT) errors.ValidationError {
	jws, jwsErr := value.JWS()
	if jwsErr != nil {
		return errors.Errorf(errors.CodeType, ctx, "Unable to get JWS from JWT", "Unable to get JWS from JWT")
	}
	if err := ruleSet.inner.Evaluate(ctx, jws); err != nil {
		return err
	}

	var output *jose.JWT
	if err := ruleSet.Apply(ctx, value, &output); err != nil {
		return err
	}

	currentRuleSet := ruleSet
	for currentRuleSet != nil {
		if currentRuleSet.rule != nil {
			if err := currentRuleSet.rule.Evaluate(ctx, value); err != nil {
				return err
			}
		}
		currentRuleSet = currentRuleSet.parent
	}

	return nil
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
