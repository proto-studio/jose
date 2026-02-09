package jose

import (
	"testing"
)

func TestNewHS256(t *testing.T) {
	alg := NewHS256([]byte("secret"))
	if alg == nil {
		t.Fatal("NewHS256 returned nil")
	}
	if alg.Name() != "HS256" {
		t.Errorf("Name() = %s, want HS256", alg.Name())
	}
}

func TestNewHS384(t *testing.T) {
	alg := NewHS384([]byte("secret"))
	if alg == nil {
		t.Fatal("NewHS384 returned nil")
	}
	if alg.Name() != "HS384" {
		t.Errorf("Name() = %s, want HS384", alg.Name())
	}
}

func TestHMAC_Verify(t *testing.T) {
	secret := []byte("my-secret")
	alg := NewHS256(secret)
	payload := []byte("hello")
	sig, err := alg.Sign("JWT", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !alg.Verify(sig, payload) {
		t.Error("Verify(sig, payload) = false, want true")
	}
	if alg.Verify(sig, []byte("wrong")) {
		t.Error("Verify with wrong payload should be false")
	}
}

func TestHMAC_Name(t *testing.T) {
	if NewHS256(nil).Name() != "HS256" {
		t.Error("HS256 Name() mismatch")
	}
	if NewHS384(nil).Name() != "HS384" {
		t.Error("HS384 Name() mismatch")
	}
}

func TestHMAC_AlgorithmsFor(t *testing.T) {
	alg := NewHS256([]byte("x"))
	alg.Kid = "mykid"

	got := alg.AlgorithmsFor(Header{"alg": "HS256"})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=HS256) len = %d, want 1", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "HS384"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=HS384) len = %d, want 0", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "HS256", "kid": "other"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
}
