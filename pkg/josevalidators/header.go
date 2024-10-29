package josevalidators

import (
	"context"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/validate/pkg/errors"
	"proto.zip/studio/validate/pkg/rules"
)

var algorithms []string = []string{
	"",
	"none",
	"HS256",
	"HS384",
	"HS512",
}

func noneGate(ctx context.Context, value string) errors.ValidationErrorCollection {
	if value == "" || value == "none" {
		if !jose.None() {
			return errors.Collection(errors.Errorf(errors.CodeForbidden, ctx, "Signature required"))
		}
	}

	return nil
}

var algRuleSet rules.RuleSet[string] = rules.String().WithAllowedValues(algorithms[0], algorithms[1:]...).WithRuleFunc(noneGate)
var typRuleSet rules.RuleSet[string] = rules.String().WithMinLen(1)
var kidRuleSet rules.RuleSet[string] = rules.String().WithMinLen(1)
var ctyRuleSet rules.RuleSet[string] = rules.String()
var jkuRuleSet rules.RuleSet[string] = rules.String()

var baseHeaderRuleSet rules.RuleSet[map[string]any] = rules.StringMap[any]().
	WithKey("alg", algRuleSet.Any()).
	WithKey("typ", typRuleSet.Any()).
	WithKey("kid", kidRuleSet.Any()).
	WithKey("cty", ctyRuleSet.Any()).
	WithKey("jku", jkuRuleSet.Any())

type HeaderRuleSet rules.RuleSet[map[string]any]

func Header() HeaderRuleSet {
	return baseHeaderRuleSet
}
