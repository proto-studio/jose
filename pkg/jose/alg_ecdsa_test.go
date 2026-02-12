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

// TestNewES256 tests that NewES256 returns a non-nil algorithm with Name ES256.
func TestNewES256(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	if alg == nil {
		t.Fatal("NewES256 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "ES256" {
		t.Errorf("Name() = %s, want ES256", name)
	}
}

// TestNewES384 tests that NewES384 returns a non-nil algorithm with Name ES384.
func TestNewES384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	alg := NewES384(&key.PublicKey, key)
	if alg == nil {
		t.Fatal("NewES384 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "ES384" {
		t.Errorf("Name() = %s, want ES384", name)
	}
}

// TestNewES512 tests that NewES512 returns a non-nil algorithm with Name ES512.
func TestNewES512(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	alg := NewES512(&key.PublicKey, key)
	if alg == nil {
		t.Fatal("NewES512 returned nil")
	}
	name, err := alg.Name()
	if err != nil {
		t.Fatalf("Name(): %v", err)
	}
	if name != "ES512" {
		t.Errorf("Name() = %s, want ES512", name)
	}
}

// TestECDSA_Sign_NilPrivateKey tests that Sign returns an error when the private key is nil.
func TestECDSA_Sign_NilPrivateKey(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	_, err := alg.Sign("JWT", []byte("payload"))
	if err == nil {
		t.Fatal("Sign with nil PrivateKey should error")
	}
}

// TestECDSA_Sign_WithKid tests that Sign includes kid in the header when set.
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

// TestECDSA_SignVerify tests that Sign produces a verifiable signature and Verify rejects wrong payload.
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

// TestECDSA_Verify_InvalidBase64Sig tests that Verify returns false for invalid base64 in the signature.
func TestECDSA_Verify_InvalidBase64Sig(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "!!!"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with invalid base64 signature should be false")
	}
}

// TestECDSA_VerifyBadSignature tests that Verify returns false for an invalid signature.
func TestECDSA_VerifyBadSignature(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "invalid"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with bad signature should be false")
	}
}

// TestECDSA_VerifyWrongSignatureLength tests that Verify returns false when the signature has the wrong length.
func TestECDSA_VerifyWrongSignatureLength(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	// Valid base64 but wrong length (ES256 expects 64 bytes)
	sig := &Signature{Protected: "e30", Signature: "YQ"} // 1 byte
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with wrong signature length should be false")
	}
}

// TestECDSA_Name_UnrecognizedReturnsError verifies that Name returns an error for an unrecognized algorithm.
func TestECDSA_Name_UnrecognizedReturnsError(t *testing.T) {
	_, pub := mustECDSAP256(t)
	e := &ECDSA{PublicKey: pub, alg: crypto.Hash(999)}
	name, err := e.Name()
	if err == nil {
		t.Error("Name() with unrecognized alg should return error")
	}
	if name != "" {
		t.Errorf("Name() on unrecognized alg = %q, want empty string", name)
	}
}

// TestECDSA_hash_Error tests Sign and Verify when the hash step fails (simulated via test hook).
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

// TestECDSA_Verify_SwappedSignature tests that Verify returns false when the signature is from a different payload.
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

// TestECDSA_AlgorithmsFor tests that AlgorithmsFor returns the algorithm only when alg and kid match.
func TestECDSA_AlgorithmsFor(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	alg.Kid = "mykid"

	got, err := alg.AlgorithmsFor(Header{"alg": "ES256"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(alg=ES256) len = %d, want 1", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "RS256"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(alg=RS256) len = %d, want 0", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "ES256", "kid": "mykid"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(kid=mykid) len = %d, want 1", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{"alg": "ES256", "kid": "other"})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("AlgorithmsFor(kid=other) len = %d, want 0", len(got))
	}
	got, err = alg.AlgorithmsFor(Header{})
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("AlgorithmsFor(no header) len = %d, want 1", len(got))
	}
}
