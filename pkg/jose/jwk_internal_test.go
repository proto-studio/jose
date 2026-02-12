// White-box tests for unexported JWK functions (package jose).
package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

// Test_newJWKFromRSAPublicKey_InvalidType tests that newJWKFromRSAPublicKey returns an error for an invalid type.
func Test_newJWKFromRSAPublicKey_InvalidType(t *testing.T) {
	_, err := newJWKFromRSAPublicKey(42)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if err.Error() != "invalid RSA public key type" {
		t.Errorf("err = %v", err)
	}
}

// fakeCurve implements elliptic.Curve but is not equal to P256/P384/P521, so getJWKCrv hits default.
type fakeCurve struct{ elliptic.Curve }

// Test_getJWKCrv_UnsupportedCurve tests that getJWKCrv returns an error for an unsupported curve.
func Test_getJWKCrv_UnsupportedCurve(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: &fakeCurve{elliptic.P256()},
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}
	_, err := getJWKCrv(pub)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

// TestNewJWK_FromECDSAPublicKey_UnsupportedCurve tests that NewJWK returns an error for an ECDSA key with unsupported curve.
func TestNewJWK_FromECDSAPublicKey_UnsupportedCurve(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: &fakeCurve{elliptic.P256()},
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}
	_, err := NewJWK(pub)
	if err == nil {
		t.Fatal("NewJWK with unsupported curve should error")
	}
}

// TestNewJWK_FromECDSAPrivateKey_UnsupportedCurve tests that NewJWK returns an error for an ECDSA private key with unsupported curve.
func TestNewJWK_FromECDSAPrivateKey_UnsupportedCurve(t *testing.T) {
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: &fakeCurve{elliptic.P256()},
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
		},
		D: big.NewInt(1),
	}
	_, err := NewJWK(priv)
	if err == nil {
		t.Fatal("NewJWK with unsupported curve private key should error")
	}
}
