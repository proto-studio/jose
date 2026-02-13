package josevalidators

import (
	"context"
	"strings"
	"time"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

// JWTRuleSet validates a JSON Web Token (claims, exp/nbf, and optional signature verification via the inner JWS rule set).
type JWTRuleSet struct {
	rules.NoConflict[*jose.JWT]
	inner     *JWSRuleSet
	rule      rules.Rule[*jose.JWT]   // applied to the whole JWT; nil if this node is claim-only
	claimName string                  // claim key this node validates; empty if this node has no claim rule
	claimRule rules.RuleSet[any]      // applied directly to the claim value (any); nil when claimName is empty
	evalTime  *time.Time              // time used for exp/nbf checks; nil means time.Now()
	parent    *JWTRuleSet
	label     string                 // for String(); e.g. "WithRequired()", "WithClaim(sub)"
}

// JWT creates a new jose.JWT RuleSet (parses compact JWT string and validates claims and optional signature).
func JWT() *JWTRuleSet {
	return &JWTRuleSet{
		inner: JWS(),
	}
}

// Required returns a boolean indicating if the value is allowed to be omitted when included in a nested object.
func (ruleSet *JWTRuleSet) Required() bool {
	return ruleSet.inner.required
}

// jwtCloneOption is a functional option applied when cloning a JWTRuleSet.
type jwtCloneOption func(*JWTRuleSet)

func jwtWithInner(inner *JWSRuleSet) jwtCloneOption {
	return func(c *JWTRuleSet) { c.inner = inner }
}

func jwtWithEvalTime(t *time.Time) jwtCloneOption {
	return func(c *JWTRuleSet) { c.evalTime = t }
}

func jwtWithClaim(name string, claimRuleSet rules.RuleSet[any]) jwtCloneOption {
	return func(c *JWTRuleSet) {
		c.claimName = name
		c.claimRule = claimRuleSet
	}
}

func jwtWithRule(rule rules.Rule[*jose.JWT]) jwtCloneOption {
	return func(c *JWTRuleSet) { c.rule = rule }
}

func jwtWithLabel(label string) jwtCloneOption {
	return func(c *JWTRuleSet) { c.label = label }
}

// clone returns a new rule set with shared state copied from the receiver (inner, evalTime)
// and parent set to the receiver. Options are applied to override specific fields.
func (ruleSet *JWTRuleSet) clone(options ...jwtCloneOption) *JWTRuleSet {
	c := &JWTRuleSet{
		parent:   ruleSet,
		inner:    ruleSet.inner,
		evalTime: ruleSet.evalTime,
	}
	for _, opt := range options {
		opt(c)
	}
	return c
}

// WithRequired returns a new rule set with the required flag set.
// Use WithRequired when nesting a RuleSet and the a value is not allowed to be omitted.
func (ruleSet *JWTRuleSet) WithRequired() *JWTRuleSet {
	return ruleSet.clone(jwtWithInner(ruleSet.inner.WithRequired()), jwtWithLabel("WithRequired()"))
}

// WithTime sets the time used for exp and nbf validation. By default the current time
// is used; WithTime overrides it (e.g. for testing or fixed evaluation time).
func (ruleSet *JWTRuleSet) WithTime(t time.Time) *JWTRuleSet {
	tcopy := t
	return ruleSet.clone(jwtWithEvalTime(&tcopy), jwtWithLabel("WithTime()"))
}

// Apply coerces value into a *jose.JWT, evaluates all rules, and returns the result or a ValidationError.
func (ruleSet *JWTRuleSet) Apply(ctx context.Context, input any) (*jose.JWT, errors.ValidationError) {
	jws, err := ruleSet.inner.Apply(ctx, input)
	if err != nil {
		return nil, err
	}

	jwt, conversionErr := jose.JWTFromJWS(jws)
	if conversionErr != nil {
		return nil, errors.Errorf(errors.CodeType, ctx, "Unable to convert JWS to JWT", "Unable to convert JWS to JWT")
	}

	newClaims, err := rules.StringMap[any]().
		WithUnknown().
		WithKey(jose.ExpirationKey, rules.Int64().Any()).
		WithKey(jose.NotBeforeKey, rules.Int64().Any()).
		Apply(ctx, jwt.Claims)
	if err != nil {
		return nil, err
	}

	jwt.Claims = newClaims

	// Pass the original parsed JWS so inner rules (e.g. Verify) run against it, not a rebuilt JWS.
	if err := ruleSet.evaluate(ctx, jwt, jws); err != nil {
		return nil, err
	}

	return jwt, nil
}

// Evaluate runs all validation rules for the given JWT. Apply calls evaluate(ctx, jwt, jws) so
// inner rules run against the original parsed JWS; other callers use Evaluate(ctx, jwt) which
// rebuilds JWS from the JWT.
func (ruleSet *JWTRuleSet) Evaluate(ctx context.Context, value *jose.JWT) errors.ValidationError {
	return ruleSet.evaluate(ctx, value, nil)
}

// claimUnix returns the claim value as Unix seconds, or (0, false) if missing or not a number.
func claimUnix(claims jose.Claims, key string) (int64, bool) {
	v, ok := claims[key]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	default:
		return 0, false
	}
}

// checkExpNbf validates exp (must be after evalTime) and nbf (must be before or at evalTime).
// Appends validation errors to errs.
func (ruleSet *JWTRuleSet) checkExpNbf(ctx context.Context, value *jose.JWT, now time.Time, errs *[]error) {
	nowUnix := now.Unix()
	if exp, ok := claimUnix(value.Claims, jose.ExpirationKey); ok {
		if nowUnix >= exp {
			*errs = append(*errs, errors.Errorf(errors.CodeExpired, ctx, "token expired", "token expired at %d", exp))
		}
	}
	if nbf, ok := claimUnix(value.Claims, jose.NotBeforeKey); ok {
		if nowUnix < nbf {
			*errs = append(*errs, errors.Errorf(errors.CodeNotAllowed, ctx, "token not yet valid", "token not valid before %d", nbf))
		}
	}
}

// applyClaimRules runs each claim rule in the chain. Each rule is applied directly to
// the claim value (any); the result is written back so the claim is mutated. Claim
// rules are cumulative: multiple rules for the same claim run in chain order, each
// receiving the previous rule's output. All claim rules are run; errors are
// accumulated and returned via errors.Join. Mutations are applied only when there
// are no errors.
func (ruleSet *JWTRuleSet) applyClaimRules(ctx context.Context, value *jose.JWT) errors.ValidationError {
	currentClaims := make(jose.Claims)
	if value.Claims != nil {
		for k, v := range value.Claims {
			currentClaims[k] = v
		}
	}

	var errs []error
	current := ruleSet
	for current != nil {
		if current.claimName != "" && current.claimRule != nil {
			claimVal := currentClaims[current.claimName]
			result, err := current.claimRule.Apply(ctx, claimVal)
			if err != nil {
				errs = append(errs, err)
			} else {
				currentClaims[current.claimName] = result
			}
		}
		current = current.parent
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	value.Claims = currentClaims
	return nil
}

// evaluate is the single validation path. When originalJWS is non-nil (from Apply), inner rules
// run against it; otherwise jws is built from value.JWS(). All rule errors are accumulated
// and returned via errors.Join.
func (ruleSet *JWTRuleSet) evaluate(ctx context.Context, value *jose.JWT, originalJWS *jose.JWS) errors.ValidationError {
	var errs []error

	if err := ruleSet.applyClaimRules(ctx, value); err != nil {
		errs = append(errs, err)
	}

	now := time.Now()
	if ruleSet.evalTime != nil {
		now = *ruleSet.evalTime
	}
	ruleSet.checkExpNbf(ctx, value, now, &errs)

	var jws *jose.JWS
	if originalJWS != nil {
		jws = originalJWS
	} else {
		var err error
		jws, err = value.JWS()
		if err != nil {
			errs = append(errs, errors.Errorf(errors.CodeType, ctx, "Unable to get JWS from JWT", "Unable to get JWS from JWT"))
		}
	}

	if jws != nil {
		if err := ruleSet.inner.Evaluate(ctx, jws); err != nil {
			errs = append(errs, err)
		}
	}

	currentRuleSet := ruleSet
	for currentRuleSet != nil {
		// rule applies to the whole JWT; claim rules already ran in applyClaimRules
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

// WithClaim returns a new rule set that validates and mutates a specific claim. The
// rule set is applied directly to the claim value (any); the result is written back
// to the claim. Use rules from proto.zip/studio/validate/pkg/rules and call .Any()
// so the type matches RuleSet[any].
//
// Example: JWT().WithClaim(jose.SubjectKey, rules.String().WithRequired().Any())
func (ruleSet *JWTRuleSet) WithClaim(name string, claimRuleSet rules.RuleSet[any]) *JWTRuleSet {
	return ruleSet.clone(jwtWithClaim(name, claimRuleSet), jwtWithLabel("WithClaim("+name+")"))
}

// WithRule returns a new child rule set with a rule added to the list of
// rules to evaluate. WithRule takes an implementation of the Rule interface
// for the jose.JWT type.
//
// Use this when implementing custom rules.
func (ruleSet *JWTRuleSet) WithRule(rule rules.Rule[*jose.JWT]) *JWTRuleSet {
	return ruleSet.clone(jwtWithRule(rule), jwtWithLabel(rule.String()))
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

// String returns a string representation of the rule set suitable for debugging,
// e.g. "JWTRuleSet", "JWTRuleSet.WithRequired()", "JWTRuleSet.WithClaim(sub)".
func (ruleSet *JWTRuleSet) String() string {
	const base = "JWTRuleSet"
	var labels []string
	for n := ruleSet; n != nil; n = n.parent {
		if n.label != "" {
			labels = append(labels, n.label)
		}
	}
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	if len(labels) == 0 {
		return base
	}
	return base + "." + strings.Join(labels, ".")
}
