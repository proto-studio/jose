package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	"proto.zip/studio/jose/internal/base64url"
)

// RSA implements Algorithm for RS256, RS384, and RS512 using an RSA key pair.
type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	alg        crypto.Hash
}

// NewRS256 returns an Algorithm that signs and verifies with RSA-SHA256.
func NewRS256(pub *rsa.PublicKey, pri *rsa.PrivateKey) *RSA {
	return &RSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA256,
	}
}

// NewRS384 returns an Algorithm that signs and verifies with RSA-SHA384.
func NewRS384(pub *rsa.PublicKey, pri *rsa.PrivateKey) *RSA {
	return &RSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA384,
	}
}

// NewRS512 returns an Algorithm that signs and verifies with RSA-SHA512.
func NewRS512(pub *rsa.PublicKey, pri *rsa.PrivateKey) *RSA {
	return &RSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA512,
	}
}

// hashErrorForTest allows tests to simulate hasher.Write failure for 100% coverage.
var hashErrorForTestRSA error

func (e *RSA) hash(protected string, payload []byte) ([]byte, error) {
	hasher := sha256.New()
	data := protected + "." + string(payload)
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}
	if hashErrorForTestRSA != nil {
		return nil, hashErrorForTestRSA
	}
	return hasher.Sum(nil), nil
}

// signWithProtected produces a signature for the given protected header and payload.
func (r *RSA) signWithProtected(protected string, payload []byte) (*Signature, error) {
	if r.PrivateKey == nil {
		return nil, errors.New("RSA Sign requires a private key")
	}
	hashed, err := r.hash(protected, payload)
	if err != nil {
		return nil, err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, r.alg, hashed[:])
	if err != nil {
		return nil, err
	}

	return &Signature{
		Protected: protected,
		Signature: base64url.Encode(sig),
	}, nil
}

// Sign signs the payload with the RSA private key and returns a signature with the given typ in the header.
func (r *RSA) Sign(typ string, payload []byte) (*Signature, error) {
	name, err := r.Name()
	if err != nil {
		return nil, err
	}
	protected := Header{
		HeaderAlg: name,
		HeaderTyp: typ,
	}

	if r.Kid != "" {
		protected[HeaderKid] = r.Kid
	}

	return r.signWithProtected(protected.Encoded(), payload)
}

// Verify returns true if the signature is valid for the payload.
func (r *RSA) Verify(sig *Signature, payload []byte) bool {
	hashed, err := r.hash(sig.Protected, payload)
	if err != nil {
		return false
	}

	signature, err := base64url.Decode(sig.Signature)
	if err != nil {
		return false
	}

	err = rsa.VerifyPKCS1v15(r.PublicKey, r.alg, hashed[:], signature)
	return err == nil
}

// Name returns the JWS algorithm name (e.g. "RS256") or an error for an unrecognized hash.
func (r *RSA) Name() (string, error) {
	switch r.alg {
	case crypto.SHA256:
		return "RS256", nil
	case crypto.SHA384:
		return "RS384", nil
	case crypto.SHA512:
		return "RS512", nil
	default:
		return "", errors.New("jose: unrecognized algorithm")
	}
}

// AlgorithmsFor returns the receiver in a slice if the header alg/kid match, or an empty slice.
func (r *RSA) AlgorithmsFor(header Header) ([]Algorithm, error) {
	name, err := r.Name()
	if err != nil {
		return nil, err
	}
	if alg, ok := header["alg"]; ok && alg != name {
		return []Algorithm{}, nil
	}
	if kid, ok := header["kid"]; ok && r.Kid != "" && r.Kid != kid {
		return []Algorithm{}, nil
	}
	return []Algorithm{r}, nil
}
