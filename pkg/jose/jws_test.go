package jose_test

import (
	"testing"

	"proto.zip/studio/jose/pkg/jose"
)

// Requirements:
// - FullHeader returns an empty map if both protected and headers are unset.
// - FullHeader returns the unprotected header.
// - FullHeader returns the protected header.
// - Protected header takes priority.
func TestGetFullHeader(t *testing.T) {
	jws := jose.JWS{}

	head, err := jws.FullHeader()

	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	}

	jws.Header = make(jose.Header)
	jws.Header[jose.HeaderAlg] = "none"
	jws.Header[jose.HeaderKid] = "abc"

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else if alg, _ := head[jose.HeaderAlg]; alg != "none" {
		t.Errorf("Expected Algorithm to be `%s`, got: %s", "none", alg)
	}

	jws.Protected = "eyJhbGciOiJIUzI1NiJ9"

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else {
		if alg, _ := head[jose.HeaderAlg]; alg != "HS256" {
			t.Errorf("Expected Algorithm to be `%s`, got: %s", "HS256", alg)
		}
		if kid, _ := head[jose.HeaderKid]; kid != "abc" {
			t.Errorf("Expected Kid to be `%s`, got: %s", "abc", kid)
		}
	}

	jws.Header = nil

	head, err = jws.FullHeader()
	if err != nil {
		t.Errorf("Expected error to be nil, got: %s", err)
	}
	if head == nil {
		t.Errorf("Expected full header to not be nil")
	} else {
		if alg, _ := head[jose.HeaderAlg]; alg != "HS256" {
			t.Errorf("Expected Algorithm to be `%s`, got: %s", "HS256", alg)
		}
		if kid, ok := head[jose.HeaderKid]; ok {
			t.Errorf("Expected Kid to be nil, got: %s", kid)
		}
	}
}
