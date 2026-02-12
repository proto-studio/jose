package jose

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"proto.zip/studio/jose/internal/base64url"
)

// HMAC implements Algorithm for HS256, HS384, and HS512 using a shared secret.
type HMAC struct {
	secret []byte
	alg    crypto.Hash
	Kid    string
}

// NewHS256 returns an Algorithm that signs and verifies with HMAC-SHA256.
func NewHS256(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA256,
	}
}

// NewHS384 returns an Algorithm that signs and verifies with HMAC-SHA384.
func NewHS384(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA384,
	}
}

// NewH256 returns an Algorithm that signs and verifies with HMAC-SHA256 (alias for NewHS256).
func NewH256(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA256,
	}
}

// NewHS512 returns an Algorithm that signs and verifies with HMAC-SHA512.
func NewHS512(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA512,
	}
}

func (h *HMAC) signWithProtected(protected string, payload []byte) (*Signature, error) {
	if h.secret == nil {
		return nil, errors.New("HMAC requires secret")
	}
	hmacFunc := hmac.New(h.alg.New, h.secret)
	hmacFunc.Write([]byte(protected))
	hmacFunc.Write([]byte("."))
	hmacFunc.Write(payload)

	sig := hmacFunc.Sum(nil)

	return &Signature{
		Protected: protected,
		Signature: base64url.Encode(sig),
	}, nil
}

// Sign signs the payload with HMAC and returns a signature with the given typ in the header.
func (h *HMAC) Sign(typ string, payload []byte) (*Signature, error) {
	name, err := h.Name()
	if err != nil {
		return nil, err
	}
	protected := Header{
		HeaderAlg: name,
		HeaderTyp: typ,
	}
	if h.Kid != "" {
		protected[HeaderKid] = h.Kid
	}

	return h.signWithProtected(protected.Encoded(), payload)
}

// Verify returns true if the signature is valid for the payload.
func (h *HMAC) Verify(sig *Signature, payload []byte) bool {
	expected, err := h.signWithProtected(sig.Protected, payload)
	if err != nil {
		return false
	}

	expectedSig, _ := base64url.Decode(expected.Signature)
	actualSig, err := base64url.Decode(sig.Signature)
	if err != nil {
		return false
	}

	return hmac.Equal(actualSig, expectedSig)
}

// Name returns the JWS algorithm name (e.g. "HS256") or an error for an unrecognized hash.
func (h *HMAC) Name() (string, error) {
	switch h.alg {
	case crypto.SHA256:
		return "HS256", nil
	case crypto.SHA384:
		return "HS384", nil
	case crypto.SHA512:
		return "HS512", nil
	default:
		return "", errors.New("jose: unrecognized algorithm")
	}
}

// AlgorithmsFor returns the receiver in a slice if the header alg/kid match, or an empty slice.
func (r *HMAC) AlgorithmsFor(header Header) ([]Algorithm, error) {
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
