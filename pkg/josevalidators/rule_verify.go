package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

// Implements the Rule interface for minimum length.
type verifyRule struct {
	fn func(ctx context.Context, header jose.Header) *jose.JWK
}

// Evaluate takes a context and string value and returns an error if it is not equal or greater in length than the specified value.
func (rule *verifyRule) Evaluate(ctx context.Context, value *jose.JWS) errors.ValidationErrorCollection {
	head, err := value.FullHeader()

	if err != nil {
		return errors.Collection(
			errors.Errorf(errors.CodeEncoding, ctx, "unable to decode header"),
		)
	}

	if alg := head[jose.HeaderAlg]; alg == "" || alg == "none" {
		return errors.Collection(
			errors.Errorf(errors.CodeEncoding, ctx, "JWS must be signed"),
		)
	}

	jwk := rule.fn(ctx, head)

	if ok := value.Verify(jwk); !ok {
		return errors.Collection(
			errors.Errorf(errors.CodeEncoding, ctx, "unable to verify signature"),
		)
	}

	return nil
}

// Conflict returns true for any minimum length rule.
func (rule *verifyRule) Conflict(x rules.Rule[*jose.JWS]) bool {
	_, ok := x.(*verifyRule)
	return ok
}

// String returns the string representation of the minimum verify rule.
// Example: WithVerify(...)
func (rule *verifyRule) String() string {
	return "WithVerifyFunc(...)"
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWT is signed by the  \JWK returned by the function.
// It is provided the JWS header.
func (ruleSet *JWSRuleSet) WithVerifyFunc(fn func(context.Context, jose.Header) *jose.JWK) *JWSRuleSet {
	return ruleSet.WithRule(&verifyRule{
		fn,
	})
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWT is signed by the  \JWK returned by the function.
// It is provided the JWS header.
func (ruleSet *JWTRuleSet) WithVerifyFunc(fn func(context.Context, jose.Header) *jose.JWK) *JWTRuleSet {
	return &JWTRuleSet{
		inner:  ruleSet.inner.WithVerifyFunc(fn),
		parent: ruleSet,
	}
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWS is signed by the provided JWK.
// It is provided the JWS header.
func (ruleSet *JWSRuleSet) WithVerifyJWK(jwk *jose.JWK) *JWSRuleSet {
	return ruleSet.WithRule(&verifyRule{
		fn: func(_ context.Context, _ jose.Header) *jose.JWK { return jwk },
	})
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWT is signed by the provided JWK.
// It is provided the JWS header.
func (ruleSet *JWTRuleSet) WithVerifyJWK(jwk *jose.JWK) *JWTRuleSet {
	return &JWTRuleSet{
		inner:  ruleSet.inner.WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return jwk }),
		parent: ruleSet,
	}
}
