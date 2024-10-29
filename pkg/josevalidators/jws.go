package josevalidators

import (
	"context"
	"reflect"
	"strings"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rulecontext"
	"proto.zip/studio/validate/pkg/rules"
)

// JWSImplementation is an interface that specifies data structures that can be converted to JWS.
type jwsImplementation interface {
	JWS() (*jose.JWS, error)
}

type JWSRuleSet struct {
	rules.NoConflict[*jose.JWS]
	required bool
	parent   *JWSRuleSet
	rule     rules.Rule[*jose.JWS]
}

// JWS creates a new jose.JWS RuleSet.
func JWS() *JWSRuleSet {
	return &JWSRuleSet{}
}

// Required returns a boolean indicating if the value is allowed to be omitted when included in a nested object.
func (ruleSet *JWSRuleSet) Required() bool {
	return ruleSet.required
}

// WithRequired returns a new rule set with the required flag set.
// Use WithRequired when nesting a RuleSet and the a value is not allowed to be omitted.
func (ruleSet *JWSRuleSet) WithRequired() *JWSRuleSet {
	if ruleSet.required {
		return ruleSet
	}

	return &JWSRuleSet{
		required: true,
		parent:   ruleSet,
	}
}

// Apply performs a validation of a RuleSet against a value and returns a string value or
// a ValidationErrorCollection.
func (ruleSet *JWSRuleSet) Apply(ctx context.Context, input, output any) errors.ValidationErrorCollection {
	// Ensure output is a non-nil pointer
	outputVal := reflect.ValueOf(output)
	if outputVal.Kind() != reflect.Ptr || outputVal.IsNil() {
		return errors.Collection(errors.Errorf(
			errors.CodeInternal, ctx, "Output must be a non-nil pointer",
		))
	}

	jws, errs := ruleSet.coerce(input, ctx)
	if len(errs) > 0 {
		return errs
	}

	if errs := ruleSet.Evaluate(ctx, jws); errs != nil {
		return errs
	}

	outputElem := outputVal.Elem()

	if outputElem.Kind() == reflect.Interface && outputElem.IsNil() {
		outputElem.Set(reflect.ValueOf(jws))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(jws)) {
		outputElem.Set(reflect.ValueOf(jws))
	} else {
		return errors.Collection(errors.Errorf(
			errors.CodeInternal, ctx, "Cannot assign %T to %T", jws, outputElem.Interface(),
		))
	}

	return nil
}

// coerceString attempts to coerce a string containing a compact JWS into a *jose.JWS and returns ValidationErrorCollection.
// This method will return a non-nil empty collection if there are no errors.
func (ruleSet *JWSRuleSet) coerce(value any, ctx context.Context) (*jose.JWS, errors.ValidationErrorCollection) {
	parts := strings.Split(value.(string), ".")

	allErrors := errors.Collection()

	if len(parts) < 2 {
		allErrors = append(allErrors, errors.Errorf(errors.CodePattern, ctx, "Missing payload"))
		return nil, allErrors
	}
	if len(parts) > 3 {
		allErrors = append(allErrors, errors.Errorf(errors.CodePattern, ctx, "Expected at most 3 parts, got %d", len(parts)))
		return nil, allErrors
	}

	_, err := base64url.Decode(parts[0])
	if err != nil {
		headerCtx := rulecontext.WithPathString(ctx, "header")
		allErrors = append(allErrors, errors.Errorf(errors.CodePattern, headerCtx, "Header must be Base64 URL encoded."))
	}

	_, err = base64url.Decode(parts[1])
	if err != nil {
		payloadCtx := rulecontext.WithPathString(ctx, "payload")
		allErrors = append(allErrors, errors.Errorf(errors.CodePattern, payloadCtx, "Payload must be Base64 URL encoded."))
	}

	jws := jose.JWS{
		Protected: parts[0],
		Payload:   parts[1],
	}

	if len(parts) > 2 {
		jws.Signature = parts[2]

		_, err = base64url.Decode(parts[2])
		if err != nil {
			signatureCtx := rulecontext.WithPathString(ctx, "signature")
			allErrors = append(allErrors, errors.Errorf(errors.CodePattern, signatureCtx, "Signature must be Base64 URL encoded."))
		}
	} else if !jose.None() {
		signatureCtx := rulecontext.WithPathString(ctx, "signature")
		allErrors = append(allErrors, errors.Errorf(errors.CodePattern, signatureCtx, "Signature is required."))
	}

	return &jws, allErrors
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationErrorCollection.
func (ruleSet *JWSRuleSet) Evaluate(ctx context.Context, value *jose.JWS) errors.ValidationErrorCollection {
	headerCtx := rulecontext.WithPathString(ctx, "header")
	signatureCtx := rulecontext.WithPathString(ctx, "signature")
	protectedCtx := rulecontext.WithPathString(ctx, "protected")
	payloadCtx := rulecontext.WithPathString(ctx, "payload")

	allErrors := errors.Collection()

	// If signatures is present: Signature, Header, and Protected must not be
	if value.Signatures != nil {
		if value.Signature != "" {
			allErrors = append(allErrors, errors.Errorf(errors.CodeNotAllowed, signatureCtx, "Signature is not allowed when signatures are present."))
		}
		if value.Header != nil {
			allErrors = append(allErrors, errors.Errorf(errors.CodeNotAllowed, headerCtx, "Header is not allowed when signatures are present."))
		}
		if value.Protected != "" {
			allErrors = append(allErrors, errors.Errorf(errors.CodeNotAllowed, protectedCtx, "Protected is not allowed when signatures are present."))
		}
	}

	// Validate top level values
	// Technically these checks are redundant if the value was parsed from a Compact JWS or the Signatures array is present but since we have no way right
	// now to tell if this came from a Compact signature we'll lean towards being defensive.

	if value.Protected != "" {
		_, err := base64url.Decode(value.Protected)
		if err != nil {
			allErrors = append(allErrors, errors.Errorf(errors.CodePattern, protectedCtx, "Protected must be Base64 URL encoded."))
		}
	}

	if value.Header != nil {
		var header any
		headerErrors := baseHeaderRuleSet.Apply(ctx, value.Header, &header)
		if headerErrors != nil {
			allErrors = append(allErrors, headerErrors...)
		}
	}

	// Validate payload

	if value.Payload != "" {
		_, err := base64url.Decode(value.Payload)
		if err != nil {
			allErrors = append(allErrors, errors.Errorf(errors.CodePattern, payloadCtx, "Payload must be Base64 URL encoded."))
		}
	}

	// Validate signature(s)

	if value.Signature != "" {

	}

	currentRuleSet := ruleSet
	ctx = rulecontext.WithRuleSet(ctx, ruleSet)

	for currentRuleSet != nil {
		if currentRuleSet.rule != nil {
			if errs := currentRuleSet.rule.Evaluate(ctx, value); errs != nil {
				allErrors = append(allErrors, errs...)
			}
		}
		currentRuleSet = currentRuleSet.parent
	}

	if len(allErrors) > 0 {
		return allErrors
	}
	return nil
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWT type.
//
// Use this when implementing custom rules.
func (ruleSet *JWSRuleSet) WithRule(rule rules.Rule[*jose.JWS]) *JWSRuleSet {
	return &JWSRuleSet{
		parent:   ruleSet,
		required: ruleSet.required,
		rule:     rule,
	}
}

// WithRuleFunc returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRuleFunc takes an implementation of the Rule interface
// for the jose.JWS type.
//
// Use this when implementing custom rules.
func (v *JWSRuleSet) WithRuleFunc(rule rules.RuleFunc[*jose.JWS]) *JWSRuleSet {
	return v.WithRule(rule)
}

// Any returns a new RuleSet that wraps the domain RuleSet in any Any rule set
// which can then be used in nested validation.
func (ruleSet *JWSRuleSet) Any() rules.RuleSet[any] {
	return rules.WrapAny[*jose.JWS](ruleSet)
}

// String returns a string representation of the rule set suitable for debugging.
func (ruleSet *JWSRuleSet) String() string {
	return "JWSRuleSet"
}
