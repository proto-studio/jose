package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

// verifyRule implements Rule for JWS signature verification.
// Label for String() is on the RuleSet (JWSRuleSet.withRuleAndLabel), not on the rule.
type verifyRule struct {
	fn func(ctx context.Context, header jose.Header) *jose.JWK
}

// Evaluate takes a context and string value and returns an error if it is not equal or greater in length than the specified value.
func (rule *verifyRule) Evaluate(ctx context.Context, value *jose.JWS) errors.ValidationError {
	head, err := value.FullHeader()

	if err != nil {
		return errors.Errorf(errors.CodeEncoding, ctx, "unable to decode header", "unable to decode header")
	}

	if alg := head[jose.HeaderAlg]; alg == "" || alg == "none" {
		return errors.Errorf(errors.CodeEncoding, ctx, "JWS must be signed", "JWS must be signed")
	}

	jwk := rule.fn(ctx, head)

	if ok := value.Verify(jwk); !ok {
		return errors.Errorf(errors.CodeEncoding, ctx, "unable to verify signature", "unable to verify signature")
	}

	return nil
}

// Replaces returns true if this rule should replace the given rule.
// All verify methods (WithVerifyFunc, WithVerifyJWK, WithJWK, WithJWKS, WithJWKSURL) use this rule; latest wins.
func (rule *verifyRule) Replaces(r rules.Rule[*jose.JWS]) bool {
	_, ok := r.(*verifyRule)
	return ok
}

// String returns the string representation of the verify rule (used when rule is used via WithRule).
func (rule *verifyRule) String() string {
	return "WithVerifyFunc(...)"
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWT is signed by the  \JWK returned by the function.
// It is provided the JWS header.
func (ruleSet *JWSRuleSet) WithVerifyFunc(fn func(context.Context, jose.Header) *jose.JWK) *JWSRuleSet {
	return ruleSet.withRuleAndLabel(&verifyRule{fn: fn}, "WithVerifyFunc(...)")
}

// WithVerifyFunc returns a new child RuleSet that verifies that the JWT is signed by the  \JWK returned by the function.
// It is provided the JWS header.
func (ruleSet *JWTRuleSet) WithVerifyFunc(fn func(context.Context, jose.Header) *jose.JWK) *JWTRuleSet {
	return ruleSet.clone(jwtWithInner(ruleSet.inner.WithVerifyFunc(fn)), jwtWithLabel("WithVerifyFunc(...)"))
}

// WithVerifyJWK returns a new child RuleSet that verifies the JWS using the provided JWK.
func (ruleSet *JWSRuleSet) WithVerifyJWK(jwk *jose.JWK) *JWSRuleSet {
	return ruleSet.WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return jwk })
}

// WithJWK returns a new child RuleSet that verifies the JWS using the given single JWK.
// Label is on the RuleSet ("WithJWK()"), not on the rule.
func (ruleSet *JWSRuleSet) WithJWK(jwk *jose.JWK) *JWSRuleSet {
	return ruleSet.withRuleAndLabel(
		&verifyRule{fn: func(_ context.Context, _ jose.Header) *jose.JWK { return jwk }},
		"WithJWK()",
	)
}

// WithJWKS returns a new child RuleSet that verifies the JWS using the given JWKS.
// The key is resolved by the "kid" (key ID) in the JWS header. Label is on the RuleSet ("WithJWKS()").
func (ruleSet *JWSRuleSet) WithJWKS(jwks *jose.JWKS) *JWSRuleSet {
	return ruleSet.withRuleAndLabel(
		&verifyRule{
			fn: func(_ context.Context, header jose.Header) *jose.JWK {
				kid, _ := header[jose.HeaderKid].(string)
				return jwks.GetByKid(kid)
			},
		},
		"WithJWKS()",
	)
}

// WithJWKSURL returns a new child RuleSet that verifies the JWS using the JWKS at the given URL.
// The key is resolved by the "kid" (key ID) in the JWS header. The JWKS is fetched via HTTP and
// cached globally using HTTP cache headers (ETag, Last-Modified, Cache-Control max-age), with
// conditional requests for revalidation and a minimum TTL of 10 seconds to prevent abuse.
func (ruleSet *JWSRuleSet) WithJWKSURL(url string) *JWSRuleSet {
	return ruleSet.withRuleAndLabel(
		&verifyRule{
			fn: func(ctx context.Context, header jose.Header) *jose.JWK {
				jwks, err := getJWKSFromURL(ctx, url)
				if err != nil || jwks == nil {
					return nil
				}
				kid, _ := header[jose.HeaderKid].(string)
				return jwks.GetByKid(kid)
			},
		},
		"WithJWKSURL(...)",
	)
}

// WithVerifyJWK returns a new child RuleSet that verifies the JWT using the provided JWK (delegates to inner JWS).
func (ruleSet *JWTRuleSet) WithVerifyJWK(jwk *jose.JWK) *JWTRuleSet {
	return ruleSet.clone(
		jwtWithInner(ruleSet.inner.WithVerifyFunc(func(_ context.Context, _ jose.Header) *jose.JWK { return jwk })),
		jwtWithLabel("WithVerifyJWK()"),
	)
}

// WithJWKS returns a new child RuleSet that verifies the JWS using the given JWKS (delegates to inner JWS).
func (ruleSet *JWTRuleSet) WithJWKS(jwks *jose.JWKS) *JWTRuleSet {
	return ruleSet.clone(jwtWithInner(ruleSet.inner.WithJWKS(jwks)), jwtWithLabel("WithJWKS()"))
}

// WithJWKSURL returns a new child RuleSet that verifies the JWT using the JWKS at the given URL (delegates to inner JWS).
// The cache is global and shared across validators; see JWSRuleSet.WithJWKSURL for details.
func (ruleSet *JWTRuleSet) WithJWKSURL(url string) *JWTRuleSet {
	return ruleSet.clone(jwtWithInner(ruleSet.inner.WithJWKSURL(url)), jwtWithLabel("WithJWKSURL(...)"))
}

// WithJWK returns a new child RuleSet that verifies the JWS using the given single JWK (delegates to inner JWS).
func (ruleSet *JWTRuleSet) WithJWK(jwk *jose.JWK) *JWTRuleSet {
	return ruleSet.clone(jwtWithInner(ruleSet.inner.WithJWK(jwk)), jwtWithLabel("WithJWK()"))
}
