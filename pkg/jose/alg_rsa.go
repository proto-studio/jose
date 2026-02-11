package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	"proto.zip/studio/jose/internal/base64url"
)

type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	alg        crypto.Hash
}

func NewRS256(pub *rsa.PublicKey, pri *rsa.PrivateKey) *RSA {
	return &RSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA256,
	}
}

func NewRS384(pub *rsa.PublicKey, pri *rsa.PrivateKey) *RSA {
	return &RSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA384,
	}
}

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

func (r *RSA) Sign(typ string, payload []byte) (*Signature, error) {
	protected := Header{
		HeaderAlg: r.Name(),
		HeaderTyp: typ,
	}

	if r.Kid != "" {
		protected[HeaderKid] = r.Kid
	}

	return r.signWithProtected(protected.Encoded(), payload)
}

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

func (r *RSA) Name() string {
	switch r.alg {
	case crypto.SHA256:
		return "RS256"
	case crypto.SHA384:
		return "RS384"
	case crypto.SHA512:
		return "RS512"
	default:
		panic("unrecognized algorithm")
	}
}

func (r *RSA) AlgorithmsFor(header Header) []Algorithm {
	if alg, ok := header["alg"]; ok && alg != r.Name() {
		return []Algorithm{}
	}
	if kid, ok := header["kid"]; ok && r.Kid != "" && r.Kid != kid {
		return []Algorithm{}
	}
	return []Algorithm{r}
}
