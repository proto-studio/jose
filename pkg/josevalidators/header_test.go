package josevalidators_test

import (
	"context"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
)

func TestHeader(t *testing.T) {
	// Header() returns a rule set; applying with valid header should pass
	ctx := context.Background()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	var out map[string]any
	err := josevalidators.Header().Apply(ctx, header, &out)
	if err != nil {
		t.Errorf("Header().Apply: %v", err)
	}
}

func TestHeader_NoneGate_RejectsWhenNoneDisabled(t *testing.T) {
	// Unprotected header with alg "none" when jose.None() is false should fail via noneGate
	jose.DisableNone()
	defer func() { jose.DisableNone() }()
	ctx := context.Background()
	jws := &jose.JWS{
		Protected: "eyJhbGciOiJIUzI1NiJ9",
		Payload:   "e30",
		Signature: "e30",
		Header:    jose.Header{"alg": "none", "typ": "JWT"},
	}
	err := josevalidators.JWS().Evaluate(ctx, jws)
	if err == nil {
		t.Error("expected error when alg is none and None() disabled")
	}
}

func TestHeader_NoneGate_AllowsWhenNoneEnabled(t *testing.T) {
	jose.EnableNone()
	defer jose.DisableNone()
	ctx := context.Background()
	jws := &jose.JWS{
		Protected: "eyJhbGciOiJub25lIn0",
		Payload:   "e30",
		Header:    jose.Header{"typ": "JWT"},
	}
	err := josevalidators.JWS().Evaluate(ctx, jws)
	if err != nil {
		t.Errorf("expected no error when None enabled: %v", err)
	}
}
