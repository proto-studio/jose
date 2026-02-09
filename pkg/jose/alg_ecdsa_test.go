package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestECDSA_VerifyBadSignature(t *testing.T) {
	_, pub := mustECDSAP256(t)
	alg := NewES256(pub, nil)
	sig := &Signature{Protected: "e30", Signature: "invalid"}
	if alg.Verify(sig, []byte("x")) {
		t.Error("Verify with bad signature should be false")
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
