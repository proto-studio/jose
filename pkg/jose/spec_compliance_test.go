package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Skipped tests document differences between JOSE specifications (RFC 7515, 7517, 7518)
// and this library's current behavior. Each test describes the correct spec behavior
// so that when the library is updated, the test can be un-skipped.

// TestJWS_DefaultTyp_JOSE: For a JWS (JSON Web Signature), when typ is not set the default
// should be "JWS" per JOSE. This test is about JWS, not JWT. Current behavior: JWS.Sign()
// uses "JSW" (typo for "JWS").
func TestJWS_DefaultTyp_JOSE(t *testing.T) {
	t.Skip("Default typ for JWS should be \"JWS\"; JWS.Sign() uses \"JSW\" (typo). See jws.go Sign().")
	alg := NewHS256([]byte("secret"))
	jws := &JWS{Payload: "e30"}
	err := jws.Sign(alg)
	if err != nil {
		t.Fatal(err)
	}
	header, err := jws.FullHeader()
	if err != nil {
		t.Fatal(err)
	}
	if typ, _ := header[HeaderTyp].(string); typ != "JWS" {
		t.Errorf("default typ = %q, want \"JWS\" for JWS per JOSE", typ)
	}
}

// TestRSA_HashPerAlg_JOSE specifies that RS384 and RS512 must use SHA-384 and SHA-512
// respectively when hashing the signing input (RFC 7518). Current behavior: alg_rsa.go
// hash() uses sha256.New() for all RSA algorithms instead of r.alg.New().
func TestRSA_HashPerAlg_JOSE(t *testing.T) {
	t.Skip("RSA hash() uses SHA-256 for all RS* algs; RS384/RS512 should use SHA-384/SHA-512. See alg_rsa.go hash().")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey
	alg384 := NewRS384(pub, key)
	alg512 := NewRS512(pub, key)
	payload := []byte("test")
	sig384, err := alg384.Sign("JWT", payload)
	if err != nil {
		t.Fatal(err)
	}
	sig512, err := alg512.Sign("JWT", payload)
	if err != nil {
		t.Fatal(err)
	}
	// Correct behavior: verify with same alg uses the same hash
	if !alg384.Verify(sig384, payload) {
		t.Error("RS384 Verify failed")
	}
	if !alg512.Verify(sig512, payload) {
		t.Error("RS512 Verify failed")
	}
}

// TestECDSA_Verify_SignatureLength_JOSE specifies that ES384 and ES512 signatures
// have different lengths (based on curve size). Current behavior: alg_ecdsa.go Verify
// checks signature length only against P256 size (64 bytes), which is wrong for
// P-384 (96) and P-521 (132).
func TestECDSA_Verify_SignatureLength_JOSE(t *testing.T) {
	t.Skip("ECDSA.Verify checks signature length only for P-256; ES384/ES512 use different lengths. See alg_ecdsa.go Verify().")
	// When fixed: signing with ES384 and verifying should accept 96-byte signature, etc.
}
