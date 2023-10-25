package jose

import (
	"encoding/json"

	"proto.zip/studio/jose/internal/base64url"
)

// Claims represents the set of claims conveyed by the JWT.
type Claims map[string]any

// Standard JWT claim keys.
const (
	IssuerKey     = "iss" // Issuer claim identifies the principal that issued the JWT.
	SubjectKey    = "sub" // Subject claim identifies the principal that is the subject of the JWT.
	AudienceKey   = "aud" // Audience claim identifies the recipients that the JWT is intended for.
	ExpirationKey = "exp" // Expiration Time claim identifies the expiration time on or after which the JWT must not be accepted for processing.
	NotBeforeKey  = "nbf" // Not Before claim identifies the time before which the JWT must not be accepted for processing.
	IssuedAtKey   = "iat" // Issued At claim identifies the time at which the JWT was issued.
	JWTIDKey      = "jti" // JWT ID claim provides a unique identifier for the JWT.
)

// JWT represents a JSON Web Token (JWT) which is a compact, URL-safe means of representing
// claims to be transferred between two parties.
type JWT struct {
	Claims    Claims    // The set of claims or assertions about a subject.
	Alg       Algorithm // The algorithm used for signing or encrypting the JWT.
	Signature []byte
}

// NewJWT creates a new JWT with the specified signing or encryption algorithm.
func NewJWT(alg Algorithm) *JWT {
	return &JWT{
		Claims: make(Claims),
		Alg:    alg,
	}
}

func JWTFromJWS(jws *JWS) (*JWT, error) {
	err := jws.Flatten()
	if err != nil {
		return nil, err
	}

	data, err := base64url.Decode(jws.Payload)
	if err != nil {
		return nil, err
	}

	var c Claims

	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	return &JWT{
		Claims: c,
	}, nil
}

// Compact serializes the JWT into its compact form, which is a string
// with three parts separated by dots.
//
// If Alg is nil and EnableNone() has not been called then this function will error.
// Unsigned JWT will only have two parts.
//
// Unsigned JWTs are dangerous, be sure you understand all the risks and implications
// before enabling them. They should be avoided in most applications.
func (jwt *JWT) Compact() (string, error) {
	jws, err := jwt.JWS()
	if err != nil {
		return "", err
	}
	return jws.Compact()
}

// JWS converts the JWT into a JSON Web Signature (JWS) structure.
// A JWS represents digitally signed or MACed content using JSON data structures and base64url encoding.
func (jwt *JWT) JWS() (*JWS, error) {
	jws := &JWS{}

	// Marshal the claims into a JSON string.
	payload, err := json.Marshal(jwt.Claims)
	if err != nil {
		return nil, err
	}
	jws.Payload = base64url.Encode(payload)

	// If a signing algorithm is specified, sign the JWS.
	if jwt.Alg != nil {
		err = jws.SignWithType("JWT", jwt.Alg)
		if err != nil {
			return nil, err
		}
	}

	return jws, nil
}
