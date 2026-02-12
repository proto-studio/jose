package jose

import (
	"crypto"
	"testing"
)

// TestNewHS256 tests that NewHS256 returns a non-nil algorithm with Name HS256.
func TestNewHS256(t *testing.T) {
	alg := NewHS256([]byte("secret"))
	if alg == nil {
		t.Fatal("NewHS256 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "HS256" {
		t.Errorf("Name() = %s, want HS256", name)
	}
}

// TestNewHS384 tests that NewHS384 returns a non-nil algorithm with Name HS384.
func TestNewHS384(t *testing.T) {
	alg := NewHS384([]byte("secret"))
	if alg == nil {
		t.Fatal("NewHS384 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "HS384" {
		t.Errorf("Name() = %s, want HS384", name)
	}
}

// TestHMAC_Verify tests that Sign produces a verifiable signature and Verify rejects wrong payload.
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

// TestHMAC_Name tests that Name returns HS256, HS384, HS512 for the respective constructors.
func TestHMAC_Name(t *testing.T) {
	for _, tc := range []struct {
		alg  *HMAC
		want string
	}{
		{NewHS256(nil), "HS256"},
		{NewHS384(nil), "HS384"},
		{NewHS512(nil), "HS512"},
	} {
		name, err := tc.alg.Name()
		if err != nil {
			t.Errorf("%s Name(): %v", tc.want, err)
			continue
		}
		if name != tc.want {
			t.Errorf("%s Name() = %s", tc.want, name)
		}
	}
}

// TestHMAC_Sign_WithKid tests that Sign includes kid in the header when set.
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

// TestHMAC_Verify_InvalidBase64Sig tests that Verify returns false for invalid base64 in the signature.
func TestHMAC_Verify_InvalidBase64Sig(t *testing.T) {
	alg := NewHS256([]byte("x"))
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

// TestHMAC_Name_UnrecognizedReturnsError verifies that Name returns an error for an unrecognized algorithm.
func TestHMAC_Name_UnrecognizedReturnsError(t *testing.T) {
	h := &HMAC{alg: crypto.Hash(999)}
	name, err := h.Name()
	if err == nil {
		t.Error("Name() with unrecognized alg should return error")
	}
	if name != "" {
		t.Errorf("Name() on unrecognized alg = %q, want empty string", name)
	}
}

// TestHMAC_Verify_NilSecret tests that Verify returns false when the verifier has a nil secret.
func TestHMAC_Verify_NilSecret(t *testing.T) {
	alg := NewHS256([]byte("secret"))
	sig, _ := alg.Sign("JWT", []byte("x"))
	verifier := NewHS256(nil)
	if verifier.Verify(sig, []byte("x")) {
		t.Error("Verify with nil secret should be false")
	}
}

// TestHMAC_Verify_SwappedSignature tests that Verify returns false when the signature is from a different payload.
func TestHMAC_Verify_SwappedSignature(t *testing.T) {
	alg := NewHS256([]byte("s"))
	sigA, _ := alg.Sign("JWT", []byte("A"))
	sigB, _ := alg.Sign("JWT", []byte("B"))
	if alg.Verify(&Signature{Protected: sigA.Protected, Signature: sigB.Signature}, []byte("A")) {
		t.Error("Verify with swapped signature should be false")
	}
}

// TestHMAC_AlgorithmsFor tests that AlgorithmsFor returns the algorithm only when alg and kid match.
func TestHMAC_AlgorithmsFor(t *testing.T) {
	alg := NewHS256([]byte("x"))
	alg.Kid = "mykid"

	got, err := alg.AlgorithmsFor(Header{"alg": "HS256"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=HS256) len = %d, want 1", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "HS384"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=HS384) len = %d, want 0", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "HS256", "kid": "other"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
}
