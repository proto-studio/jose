package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func mustECDSAP256(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key, &key.PublicKey
}

func TestNewES256(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	if alg == nil {
		t.Fatal("NewES256 returned nil")
	}
	if alg.Name() != "ES256" {
		t.Errorf("Name() = %s, want ES256", alg.Name())
	}
}

func TestNewES384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	alg := NewES384(&key.PublicKey, key)
	if alg == nil {
		t.Fatal("NewES384 returned nil")
	}
	if alg.Name() != "ES384" {
		t.Errorf("Name() = %s, want ES384", alg.Name())
	}
}

func TestNewES512(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	alg := NewES512(&key.PublicKey, key)
	if alg == nil {
		t.Fatal("NewES512 returned nil")
	}
	if alg.Name() != "ES512" {
		t.Errorf("Name() = %s, want ES512", alg.Name())
	}
}

func TestECDSA_Sign_NilPrivateKey(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	_, err := alg.Sign("JWT", []byte("payload"))
	if err == nil {
		t.Fatal("Sign with nil PrivateKey should error")
	}
}

func TestECDSA_Sign_WithKid(t *testing.T) {
	priv, pub := mustECDSAP256(t)
	alg := NewES256(pub, priv)
	alg.Kid = "my-key-id"
	sig, err := alg.Sign("JWT", []byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Decode protected and check kid is present
	if sig.Protected == "" {
		t.Fatal("expected protected header")
	}
	if !alg.Verify(sig, []byte("x")) {
		t.Error("Verify failed")
	}
}

func TestECDSA_SignVerify(t *testing.T) {
	priv, pub := mustECDSAP256(t)
	alg := NewES256(pub, priv)
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

func TestECDSA_Verify_InvalidBase64Sig(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

func TestECDSA_VerifyBadSignature(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "invalid"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with bad signature should be false")
	}
}

func TestECDSA_VerifyWrongSignatureLength(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	// Valid base64 but wrong length (ES256 expects 64 bytes)
	sig := &Signature{Protected: "e30", Signature: "YQ"} // 1 byte
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with wrong signature length should be false")
	}
}

// Name() with unrecognized alg panics (default branch).
func TestECDSA_Name_UnrecognizedPanics(t *testing.T) {
	_, pub := mustECDSAP256(t)
	e := &ECDSA{PublicKey: pub, alg: crypto.Hash(999)}
	defer func() {
		if r := recover(); r == nil {
			t.Error("Name() with unrecognized alg should panic")
		}
	}()
	e.Name()
}

// hash error path (simulated via test hook)
func TestECDSA_hash_Error(t *testing.T) {
	hashErrorForTestECDSA = errors.New("hash fail")
	defer func() { hashErrorForTestECDSA = nil }()
	priv, pub := mustECDSAP256(t)
	alg := NewES256(pub, priv)
	_, err := alg.Sign("JWT", []byte("x"))
	if err == nil {
		t.Fatal("Sign when hash fails should error")
	}
	_, pub2 := mustECDSAP256(t)
	alg2 := NewES256(pub2, nil)
	sig := &Signature{Protected: "e30", Signature: "YQ"} // valid base64, wrong length
	if alg2.Verify(sig, []byte("x")) {
		t.Error("Verify when hash fails should be false")
	}
}

// Sign two payloads, swap signatures: verify A with B's signature must be false.
func TestECDSA_Verify_SwappedSignature(t *testing.T) {
	priv, pub := mustECDSAP256(t)
	alg := NewES256(pub, priv)
	sigA, _ := alg.Sign("JWT", []byte("payloadA"))
	sigB, _ := alg.Sign("JWT", []byte("payloadB"))
	// Verify A's payload with B's signature
	if alg.Verify(&Signature{Protected: sigA.Protected, Signature: sigB.Signature}, []byte("payloadA")) {
		t.Error("Verify with swapped signature should be false")
	}
}

func TestECDSA_AlgorithmsFor(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	alg.Kid = "mykid"

	got := alg.AlgorithmsFor(Header{"alg": "ES256"})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=ES256) len = %d, want 1", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "RS256"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=RS256) len = %d, want 0", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "ES256", "kid": "mykid"})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(kid=mykid) len = %d, want 1", len(got))
	}
	got = alg.AlgorithmsFor(Header{"alg": "ES256", "kid": "other"})
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
	got = alg.AlgorithmsFor(Header{})
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(no header) len = %d, want 1", len(got))
	}
}
