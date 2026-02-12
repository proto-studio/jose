package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func mustRSAKey(t *testing.T, bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key, &key.PublicKey
}

// TestNewRS384 tests that NewRS384 returns a non-nil algorithm with Name RS384.
func TestNewRS384(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS384(pub, priv)
	if alg == nil {
		t.Fatal("NewRS384 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "RS384" {
		t.Errorf("Name() = %s, want RS384", name)
	}
}

// TestNewRS512 tests that NewRS512 returns a non-nil algorithm with Name RS512.
func TestNewRS512(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS512(pub, priv)
	if alg == nil {
		t.Fatal("NewRS512 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "RS512" {
		t.Errorf("Name() = %s, want RS512", name)
	}
}

// TestRSA_SignVerify tests that Sign produces a verifiable signature and Verify rejects wrong payload.
func TestRSA_SignVerify(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, priv)
	payload := []byte("test payload")
	sig, err := alg.Sign("JWT", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil || sig.Protected == "" || sig.Signature == "" {
		t.Fatal("Sign returned incomplete signature")
	}
	if !alg.Verify(sig, payload) {
		t.Error("Verify(sig, payload) = false, want true")
	}
	if alg.Verify(sig, []byte("wrong")) {
		t.Error("Verify with wrong payload should be false")
	}
}

// TestRSA_VerifyBadSignature tests that Verify returns false for an invalid signature.
func TestRSA_VerifyBadSignature(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "invalid"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with bad signature should be false")
	}
}

// TestRSA_VerifyInvalidBase64Signature tests that Verify returns false for invalid base64 in the signature.
func TestRSA_VerifyInvalidBase64Signature(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

// TestRSA_Sign_NilPrivateKey tests that Sign returns an error when the private key is nil.
func TestRSA_Sign_NilPrivateKey(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	_, err := alg.Sign("JWT", []byte("data"))
	if err == nil {
		t.Fatal("Sign with nil PrivateKey should error")
	}
}

// TestRSA_Sign_WithKid tests that Sign includes kid in the header when set.
func TestRSA_Sign_WithKid(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, priv)
	alg.Kid = "rsa-kid"
	sig, err := alg.Sign("JWT", []byte("data"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !alg.Verify(sig, []byte("data")) {
		t.Error("Verify failed")
	}
}

// TestRSA_Name_UnrecognizedReturnsError verifies that Name returns an error for an unrecognized algorithm.
func TestRSA_Name_UnrecognizedReturnsError(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := &RSA{PublicKey: pub, alg: crypto.Hash(999)}
	name, err := alg.Name()
	if err == nil {
		t.Error("Name() with unrecognized alg should return error")
	}
	if name != "" {
		t.Errorf("Name() on unrecognized alg = %q, want empty string", name)
	}
}

// TestRSA_hash_Error tests Sign and Verify when the hash step fails (simulated via test hook).
func TestRSA_hash_Error(t *testing.T) {
	hashErrorForTestRSA = errors.New("hash fail")
	defer func() { hashErrorForTestRSA = nil }()
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, priv)
	_, err := alg.Sign("JWT", []byte("x"))
	if err == nil {
		t.Fatal("Sign when hash fails should error")
	}
	_, pub2 := mustRSAKey(t, 2048)
	alg2 := NewRS256(pub2, nil)
	sig := &Signature{Protected: "e30", Signature: "e30"}
	if alg2.Verify(sig, []byte("x")) {
		t.Error("Verify when hash fails should be false")
	}
}

// TestRSA_Verify_SwappedSignature tests that Verify returns false when the signature is from a different payload.
func TestRSA_Verify_SwappedSignature(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, priv)
	sigA, _ := alg.Sign("JWT", []byte("payloadA"))
	sigB, _ := alg.Sign("JWT", []byte("payloadB"))
	if alg.Verify(&Signature{Protected: sigA.Protected, Signature: sigB.Signature}, []byte("payloadA")) {
		t.Error("Verify with swapped signature should be false")
	}
}

// TestRSA_AlgorithmsFor tests that AlgorithmsFor returns the algorithm only when alg and kid match.
func TestRSA_AlgorithmsFor(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	alg.Kid = "mykid"

	got, err := alg.AlgorithmsFor(Header{"alg": "RS256"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=RS256) len = %d, want 1", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "ES256"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=ES256) len = %d, want 0", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "RS256", "kid": "mykid"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(kid=mykid) len = %d, want 1", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "RS256", "kid": "other"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
}
