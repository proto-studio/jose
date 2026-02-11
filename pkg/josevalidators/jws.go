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

type JWSRuleSet struct {
	rules.NoConflict[*jose.JWS]
	required bool
	parent   *JWSRuleSet
	rule     rules.Rule[*jose.JWS]
	label    string // for String(); e.g. "WithRequired()", rule.String()
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
		label:    "WithRequired()",
	}
}

// Apply performs a validation of a RuleSet against a value and returns a string value or
// a ValidationError.
func (ruleSet *JWSRuleSet) Apply(ctx context.Context, input, output any) errors.ValidationError {
	// Ensure output is a non-nil pointer
	outputVal := reflect.ValueOf(output)
	if outputVal.Kind() != reflect.Ptr || outputVal.IsNil() {
		return errors.Errorf(
			errors.CodeInternal, ctx, "Output must be a non-nil pointer", "Output must be a non-nil pointer",
		)
	}

	jws, err := ruleSet.coerce(input, ctx)
	if err != nil {
		return err
	}

	if err := ruleSet.Evaluate(ctx, jws); err != nil {
		return err
	}

	outputElem := outputVal.Elem()

	if outputElem.Kind() == reflect.Interface && outputElem.IsNil() {
		outputElem.Set(reflect.ValueOf(jws))
	} else if outputElem.Type().AssignableTo(reflect.TypeOf(jws)) {
		outputElem.Set(reflect.ValueOf(jws))
	} else {
		return errors.Errorf(
			errors.CodeInternal, ctx, "Cannot assign", "Cannot assign %T to %T", jws, outputElem.Interface(),
		)
	}

	return nil
}

// coerce attempts to coerce a string containing a compact JWS into a *jose.JWS and returns a ValidationError on failure.
func (ruleSet *JWSRuleSet) coerce(value any, ctx context.Context) (*jose.JWS, errors.ValidationError) {
	parts := strings.Split(value.(string), ".")

	var errs []error

	if len(parts) < 2 {
		errs = append(errs, errors.Errorf(errors.CodePattern, ctx, "Missing payload", "Missing payload"))
		return nil, errors.Join(errs...)
	}
	if len(parts) > 3 {
		errs = append(errs, errors.Errorf(errors.CodePattern, ctx, "Expected at most 3 parts", "Expected at most 3 parts, got %d", len(parts)))
		return nil, errors.Join(errs...)
	}

	_, err := base64url.Decode(parts[0])
	if err != nil {
		headerCtx := rulecontext.WithPathString(ctx, "header")
		errs = append(errs, errors.Errorf(errors.CodePattern, headerCtx, "Header must be Base64 URL encoded", "Header must be Base64 URL encoded."))
	}

	_, err = base64url.Decode(parts[1])
	if err != nil {
		payloadCtx := rulecontext.WithPathString(ctx, "payload")
		errs = append(errs, errors.Errorf(errors.CodePattern, payloadCtx, "Payload must be Base64 URL encoded", "Payload must be Base64 URL encoded."))
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
			errs = append(errs, errors.Errorf(errors.CodePattern, signatureCtx, "Signature must be Base64 URL encoded", "Signature must be Base64 URL encoded."))
		}
	} else if !jose.None() {
		signatureCtx := rulecontext.WithPathString(ctx, "signature")
		errs = append(errs, errors.Errorf(errors.CodePattern, signatureCtx, "Signature is required", "Signature is required."))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &jws, nil
}

// Evaluate performs a validation of a RuleSet against a string value and returns a string value of the
// same type or a ValidationError.
func (ruleSet *JWSRuleSet) Evaluate(ctx context.Context, value *jose.JWS) errors.ValidationError {
	headerCtx := rulecontext.WithPathString(ctx, "header")
	signatureCtx := rulecontext.WithPathString(ctx, "signature")
	protectedCtx := rulecontext.WithPathString(ctx, "protected")
	payloadCtx := rulecontext.WithPathString(ctx, "payload")

	var errs []error

	// If signatures is present: Signature, Header, and Protected must not be
	if value.Signatures != nil {
		if value.Signature != "" {
			errs = append(errs, errors.Errorf(errors.CodeNotAllowed, signatureCtx, "Signature not allowed", "Signature is not allowed when signatures are present."))
		}
		if value.Header != nil {
			errs = append(errs, errors.Errorf(errors.CodeNotAllowed, headerCtx, "Header not allowed", "Header is not allowed when signatures are present."))
		}
		if value.Protected != "" {
			errs = append(errs, errors.Errorf(errors.CodeNotAllowed, protectedCtx, "Protected not allowed", "Protected is not allowed when signatures are present."))
		}
	}

	// Validate top level values
	// Technically these checks are redundant if the value was parsed from a Compact JWS or the Signatures array is present but since we have no way right
	// now to tell if this came from a Compact signature we'll lean towards being defensive.

	if value.Protected != "" {
		_, err := base64url.Decode(value.Protected)
		if err != nil {
			errs = append(errs, errors.Errorf(errors.CodePattern, protectedCtx, "Protected must be Base64 URL encoded", "Protected must be Base64 URL encoded."))
		}
	}

	if value.Header != nil {
		var header any
		if headerErr := baseHeaderRuleSet.Apply(ctx, value.Header, &header); headerErr != nil {
			errs = append(errs, headerErr)
		}
	}

	// Validate payload

	if value.Payload != "" {
		_, err := base64url.Decode(value.Payload)
		if err != nil {
			errs = append(errs, errors.Errorf(errors.CodePattern, payloadCtx, "Payload must be Base64 URL encoded", "Payload must be Base64 URL encoded."))
		}
	}

	// Validate signature(s)

	if value.Signature != "" {

	}

	currentRuleSet := ruleSet
	ctx = rulecontext.WithRuleSet(ctx, ruleSet)

	for currentRuleSet != nil {
		if currentRuleSet.rule != nil {
			if err := currentRuleSet.rule.Evaluate(ctx, value); err != nil {
				errs = append(errs, err)
			}
		}
		currentRuleSet = currentRuleSet.parent
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// noConflict returns a new chain with any node that the checker replaces removed.
// Used so that conflicting rules (e.g. WithJWK vs WithJWKS) keep only the latest.
func (ruleSet *JWSRuleSet) noConflict(checker rules.Rule[*jose.JWS]) *JWSRuleSet {
	conflicts := false
	if ruleSet.rule != nil && checker.Replaces(ruleSet.rule) {
		conflicts = true
	}
	if conflicts {
		if ruleSet.parent == nil {
			return nil
		}
		return ruleSet.parent.noConflict(checker)
	}
	if ruleSet.parent == nil {
		return ruleSet
	}
	newParent := ruleSet.parent.noConflict(checker)
	if newParent == ruleSet.parent {
		return ruleSet
	}
	return &JWSRuleSet{
		parent:   newParent,
		required: ruleSet.required,
		rule:     ruleSet.rule,
		label:    ruleSet.label,
	}
}

// withRuleAndLabel returns a new child rule set with the rule and an explicit label.
// Built-in methods (WithJWK, WithJWKS, WithJWKSURL, WithVerifyFunc) use this so the label is on the RuleSet.
func (ruleSet *JWSRuleSet) withRuleAndLabel(rule rules.Rule[*jose.JWS], label string) *JWSRuleSet {
	return &JWSRuleSet{
		parent:   ruleSet.noConflict(rule),
		required: ruleSet.required,
		rule:     rule,
		label:    label,
	}
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWS type. If the rule implements Replaces, any ancestor rule
// it replaces is removed from the chain (latest wins).
//
// Use this when implementing custom rules.
func (ruleSet *JWSRuleSet) WithRule(rule rules.Rule[*jose.JWS]) *JWSRuleSet {
	return ruleSet.withRuleAndLabel(rule, rule.String())
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

// String returns a string representation of the rule set suitable for debugging,
// e.g. "JWSRuleSet", "JWSRuleSet.WithRequired()", "JWSRuleSet.WithJWK()".
func (ruleSet *JWSRuleSet) String() string {
	const base = "JWSRuleSet"
	var labels []string
	for n := ruleSet; n != nil; n = n.parent {
		if n.label != "" {
			labels = append(labels, n.label)
		}
	}
	// labels are leaf-first; we want root-to-leaf for display
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	if len(labels) == 0 {
		return base
	}
	return base + "." + strings.Join(labels, ".")
}
