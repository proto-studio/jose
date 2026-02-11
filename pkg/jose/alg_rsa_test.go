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

func TestNewRS384(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS384(pub, priv)
	if alg == nil {
		t.Fatal("NewRS384 returned nil")
	}
	if alg.Name() != "RS384" {
		t.Errorf("Name() = %s, want RS384", alg.Name())
	}
}

func TestNewRS512(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS512(pub, priv)
	if alg == nil {
		t.Fatal("NewRS512 returned nil")
	}
	if alg.Name() != "RS512" {
		t.Errorf("Name() = %s, want RS512", alg.Name())
	}
}

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

func TestRSA_VerifyBadSignature(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "invalid"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with bad signature should be false")
	}
}

func TestRSA_VerifyInvalidBase64Signature(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

func TestRSA_Sign_NilPrivateKey(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	_, err := alg.Sign("JWT", []byte("data"))
	if err == nil {
		t.Fatal("Sign with nil PrivateKey should error")
	}
}

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

// Name() with unrecognized alg panics.
func TestRSA_Name_UnrecognizedPanics(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := &RSA{PublicKey: pub, alg: crypto.Hash(999)}
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("Name() with unrecognized alg should panic")
		}
	}()
	alg.Name()
}

// hash error path (simulated via test hook)
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

// Sign two payloads, swap signatures: verify A with B's signature must be false.
func TestRSA_Verify_SwappedSignature(t *testing.T) {
	priv, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, priv)
	sigA, _ := alg.Sign("JWT", []byte("payloadA"))
	sigB, _ := alg.Sign("JWT", []byte("payloadB"))
	if alg.Verify(&Signature{Protected: sigA.Protected, Signature: sigB.Signature}, []byte("payloadA")) {
		t.Error("Verify with swapped signature should be false")
	}
}

func TestRSA_AlgorithmsFor(t *testing.T) {
	_, pub := mustRSAKey(t, 2048)
	alg := NewRS256(pub, nil)
	alg.Kid = "mykid"

	got := alg.AlgorithmsFor(Header{"alg": "RS256"})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=RS256) len = %d, want 1", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "ES256"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=ES256) len = %d, want 0", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "RS256", "kid": "mykid"})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(kid=mykid) len = %d, want 1", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "RS256", "kid": "other"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
}
