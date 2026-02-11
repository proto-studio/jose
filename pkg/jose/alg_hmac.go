package jose

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"proto.zip/studio/jose/internal/base64url"
)

type HMAC struct {
	secret []byte
	alg    crypto.Hash
	Kid    string
}

func NewHS256(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA256,
	}
}

func NewHS384(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA384,
	}
}

func NewH256(secret []byte) *HMAC {
	return &HMAC{
		secret: secret,
		alg:    crypto.SHA256,
	}
}

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

func (h *HMAC) Sign(typ string, payload []byte) (*Signature, error) {
	protected := Header{
		HeaderAlg: h.Name(),
		HeaderTyp: typ,
	}
	if h.Kid != "" {
		protected[HeaderKid] = h.Kid
	}

	return h.signWithProtected(protected.Encoded(), payload)
}

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

func (h *HMAC) Name() string {
	switch h.alg {
	case crypto.SHA256:
		return "HS256"
	case crypto.SHA384:
		return "HS384"
	case crypto.SHA512:
		return "HS512"
	default:
		panic("unrecognized algorithm")
	}
}

func (r *HMAC) AlgorithmsFor(header Header) []Algorithm {
	if alg, ok := header["alg"]; ok && alg != r.Name() {
		return []Algorithm{}
	}
	if kid, ok := header["kid"]; ok && r.Kid != "" && r.Kid != kid {
		return []Algorithm{}
	}
	return []Algorithm{r}
}
