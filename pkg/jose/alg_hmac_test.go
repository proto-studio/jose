package jose

import (
	"crypto"
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
	if NewHS512(nil).Name() != "HS512" {
		t.Error("HS512 Name() mismatch")
	}
}

func TestHMAC_Sign_WithKid(t *testing.T) {
	alg := NewHS256([]byte("secret"))
	alg.Kid = "mykid"
	sig, err := alg.Sign("JWT", []byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Protected == "" {
		t.Fatal("expected protected")
	}
	if !alg.Verify(sig, []byte("payload")) {
		t.Error("Verify failed")
	}
}

func TestHMAC_Verify_InvalidBase64Sig(t *testing.T) {
	alg := NewHS256([]byte("x"))
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

// Name() with unrecognized alg panics.
func TestHMAC_Name_UnrecognizedPanics(t *testing.T) {
	h := &HMAC{alg: crypto.Hash(999)}
	defer func() {
		if r := recover(); r == nil {
			t.Error("Name() with unrecognized alg should panic")
		}
	}()
	h.Name()
}

// Verify when signWithProtected fails (nil secret) returns false.
func TestHMAC_Verify_NilSecret(t *testing.T) {
	alg := NewHS256([]byte("secret"))
	sig, _ := alg.Sign("JWT", []byte("x"))
	verifier := NewHS256(nil)
	if verifier.Verify(sig, []byte("x")) {
		t.Error("Verify with nil secret should be false")
	}
}

// Sign two payloads, swap signatures: verify A with B's signature must be false.
func TestHMAC_Verify_SwappedSignature(t *testing.T) {
	alg := NewHS256([]byte("s"))
	sigA, _ := alg.Sign("JWT", []byte("A"))
	sigB, _ := alg.Sign("JWT", []byte("B"))
	if alg.Verify(&Signature{Protected: sigA.Protected, Signature: sigB.Signature}, []byte("A")) {
		t.Error("Verify with swapped signature should be false")
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
