package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"proto.zip/studio/jose/internal/base64url"
)

type ECDSA struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Kid        string
	alg        crypto.Hash
}

func NewES256(pub *ecdsa.PublicKey, pri *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA256,
	}
}

func NewES384(pub *ecdsa.PublicKey, pri *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA384,
	}
}

func NewES512(pub *ecdsa.PublicKey, pri *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		PublicKey:  pub,
		PrivateKey: pri,
		alg:        crypto.SHA512,
	}
}

// hashErrorForTest allows tests to simulate hasher.Write failure for 100% coverage.
var hashErrorForTestECDSA error

func (e *ECDSA) hash(protected string, payload []byte) ([]byte, error) {
	hasher := e.alg.New()
	data := protected + "." + string(payload)
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}
	if hashErrorForTestECDSA != nil {
		return nil, hashErrorForTestECDSA
	}
	return hasher.Sum(nil), nil
}

func (e *ECDSA) Sign(typ string, payload []byte) (*Signature, error) {
	protected := Header{
		HeaderAlg: e.Name(),
		HeaderTyp: typ,
	}
	if e.Kid != "" {
		protected[HeaderKid] = e.Kid
	}

	protectedStr := protected.Encoded()

	if e.PrivateKey == nil {
		return nil, errors.New("ECDSA Sign requires a private key")
	}

	hash, err := e.hash(protectedStr, payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}
	curveSize := e.PrivateKey.Curve.Params().BitSize / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*curveSize)
	copy(sig[curveSize-len(rBytes):], rBytes)
	copy(sig[2*curveSize-len(sBytes):], sBytes)

	return &Signature{
		Protected: protectedStr,
		Signature: base64url.Encode(sig),
	}, nil

}

func (e *ECDSA) Verify(sig *Signature, payload []byte) bool {
	signature, err := base64url.Decode(sig.Signature)
	if err != nil {
		return false
	}

	if len(signature) != 2*elliptic.P256().Params().BitSize/8 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	hash, err := e.hash(sig.Protected, payload)
	if err != nil {
		return false
	}
	return ecdsa.Verify(e.PublicKey, hash[:], r, s)
}

func (r *ECDSA) Name() string {
	switch r.alg {
	case crypto.SHA256:
		return "ES256"
	case crypto.SHA384:
		return "ES384"
	case crypto.SHA512:
		return "ES512"
	default:
		panic("unrecognized algorithm")
	}
}

func (r *ECDSA) AlgorithmsFor(header Header) []Algorithm {
	if alg, ok := header["alg"]; ok && alg != r.Name() {
		return []Algorithm{}
	}
	if kid, ok := header["kid"]; ok && r.Kid != "" && r.Kid != kid {
		return []Algorithm{}
	}
	return []Algorithm{r}
}
