package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func (e *ECDSA) hash(protected string, payload []byte) ([]byte, error) {
	hasher := e.alg.New()
	data := protected + "." + string(payload)
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (e *ECDSA) Sign(typ string, payload []byte) (*Signature, error) {
	protected := Header{
		HeaderAlg: e.Name(),
		HeaderKid: e.Kid,
		HeaderTyp: typ,
	}.Encoded()

	hash, err := e.hash(protected, payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.Bytes(), s.Bytes()...)

	return &Signature{
		Protected: protected,
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
