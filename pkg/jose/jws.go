package jose

import (
	"encoding/json"
	"errors"

	"proto.zip/studio/jose/internal/base64url"
)

const (
	// HeaderAlg represents the algorithm used to secure the JWS.
	HeaderAlg string = "alg"

	// HeaderKid represents the key ID hint indicating the specific key used to secure the JWS.
	HeaderKid string = "kid"

	// HeaderTyp represents the type of token, which is typically "JWT" for JSON Web Tokens.
	HeaderTyp string = "typ"

	// HeaderCty represents the content type of the JWS, to declare the media type of the secured content.
	HeaderCty string = "cty"

	// HeaderJku represents the URL for the JSON Web Key Set (JWKS) where the key for the JWS can be obtained.
	HeaderJku string = "jku"

	// HeaderJwk represents the JSON Web Key (JWK) corresponding to the key used to digitally sign the JWS.
	HeaderJwk string = "jwk"

	// HeaderX5u represents the URL for the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS.
	HeaderX5u string = "x5u"

	// HeaderX5c represents the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS.
	HeaderX5c string = "x5c"

	// HeaderX5t represents the X.509 certificate SHA-1 thumbprint (a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate).
	HeaderX5t string = "x5t"

	// HeaderX5tS256 represents the X.509 certificate SHA-256 thumbprint (a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate).
	HeaderX5tS256 string = "x5t#S256"

	// HeaderCrit represents the critical header parameter indicating that extensions to the JWS standard are being used that must be understood and processed.
	HeaderCrit string = "crit"
)

// Header represents the header section of a JWS.
type Header map[string]any

// Encoded returns the base64url-encoded JSON of the header.
func (h Header) Encoded() string {
	data, _ := json.Marshal(h)
	return base64url.Encode(data)
}

// Signature holds the protected header, optional unprotected header, and signature value for one signer.
type Signature struct {
	Protected string `json:"protected,omitempty"`
	Header    Header `json:"header,omitempty"`
	Signature string `json:"signature"`
}

// Decoded returns the raw signature bytes from the base64url-encoded Signature field.
func (sig *Signature) Decoded() ([]byte, error) {
	return base64url.Decode(sig.Signature)
}

// JWS is a JSON Web Signature: signed or MACed payload with one or more signatures.
type JWS struct {
	Payload string `json:"payload"`

	// Expanded
	Signatures []Signature `json:"signatures,omitempty"`

	// Compact
	Protected string `json:"protected,omitempty"`
	Header    Header `json:"header,omitempty"`
	Signature string `json:"signature"`

	// Internal use
	typ string
}

// Sign applies each of the algorithms to the JWS and adds them to the signatures array.
//
// Headers are auto-generated and this function does not support unprotected header value or
// customized header fields. To support custom headers or unprotected headers, you may create
// the signatures manually.
//
// The JWS will be flat by default until more than one signature is added.
//
// The "typ" value will be "JWS". If you wish to have a different type, use SignWithType() instead.
func (jws *JWS) Sign(alg ...Algorithm) error {
	typ := jws.typ
	if typ == "" {
		typ = "JSW"
	}

	return jws.SignWithType(typ, alg...)
}

// SignWithType applies each of the algorithms to the JWS and adds them to the signatures array.
//
// The generated header will have the "typ" value specified.
//
// Headers are auto-generated and this function does not support unprotected header value or
// customized header fields. To support custom headers or unprotected headers, you may create
// the signatures manually.
//
// The JWS will be flat by default until more than one signature is added.
//
// If an empty string is passed in then the resulting header will have no "typ" value.
func (jws *JWS) SignWithType(typ string, alg ...Algorithm) error {
	if len(alg) == 0 {
		return errors.New("no algorithms to sign with")
	}

	if jws.Signatures == nil {
		if jws.Signature != "" {
			// We currently have a signed flat JWS and want to add to it.
			// Move the current signature to the array.
			jws.Signatures = make([]Signature, 1, len(alg)+1)
			jws.Signatures[0].Signature = jws.Signature
			jws.Signatures[0].Protected = jws.Protected
			jws.Signatures[0].Header = jws.Header

			// Clear the top-level values.
			jws.Header = nil
			jws.Signature = ""
			jws.Protected = ""
		} else if len(alg) > 1 {
			jws.Signatures = make([]Signature, 0, len(alg))
		}
	}

	p := []byte(jws.Payload)

	// If the Signatures is still nil that means we're signing a flat JWS.
	if jws.Signatures == nil {
		sig, err := alg[0].Sign(typ, p)

		if err != nil {
			return err
		}

		jws.Signature = sig.Signature
		jws.Protected = sig.Protected
		jws.Header = sig.Header
	} else {
		for i := range alg {
			sig, err := alg[i].Sign(typ, p)

			if err != nil {
				return err
			}

			jws.Signatures = append(jws.Signatures, *sig)
		}
	}

	return nil
}

// Compact returns the string compact representation of the JSE.
// Compact JSEs can only have one signature, so calling this method with a JSE that has more than one
// signature will return an error.
//
// This method will automatically flatten the JWS.
//
// Compact representations do not support unprotected header fields.
//
// The Compact JSE has 3 parts all separated by dots:
// 1. The header contains Json encoded information on the signing of the JSE.
// 2. The payload is an arbitrary string of bytes to be signed.
// 3. The signature.
//
// All 3 parts are base64 url encoded.
// If there are no signatures, the compact representation will only have two parts.
//
// By default unsigned compact JSWs are disabled. Call EnableNone() to allow JSEs with no signature.
func (jws *JWS) Compact() (string, error) {
	err := jws.Flatten()
	if err != nil {
		return "", err
	}

	if jws.Signature == "" && !None() {
		return "", errors.New("signature is required; call EnableNone() to allow unsigned JWS")
	}

	if jws.Header != nil {
		return "", errors.New("unprotected headers are not supported by the compact representation")
	}

	if jws.Signature == "" {
		return jws.Protected + "." + jws.Payload, nil
	} else {
		return jws.Protected + "." + jws.Payload + "." + jws.Signature, nil
	}
}

// Flatten takes the JWS and moves the first signature to the top level.
// A flat JWS does not support multiple signatures and this method will error if there is more than
// one signature already.
//
// Calling Flatten on an already flat JWS does not do anything.
//
// Calling Compact will automatically flatten the JWS. By default any compact JWS will be flat after parsing.
//
// the Expand method will reverse this operation and create an expanded JWS.
// Calling Sign on a flat signed JWS will automatically expand it again.
func (jws *JWS) Flatten() error {
	l := len(jws.Signatures)

	if l > 1 {
		return errors.New("cannot flatten because there is more than one signature")
	}
	if l == 1 {
		jws.Signature = jws.Signatures[0].Signature
		jws.Protected = jws.Signatures[0].Protected
		jws.Header = jws.Signatures[0].Header
		jws.Signatures = nil
	}

	return nil
}

// Verify returns a boolean indicating if the signature is valid based on the provided JWT.
func (jws *JWS) Verify(jwk *JWK) bool {
	if jwk == nil {
		return false
	}

	header, err := jws.FullHeader()

	if err != nil {
		return false
	}

	algName, _ := header[HeaderAlg].(string)
	alg, err := jwk.Algorithm(algName)

	if alg == nil || err != nil {
		return false
	}

	if jws.Signatures != nil {
		for i := range jws.Signatures {
			if alg.Verify(&jws.Signatures[i], []byte(jws.Payload)) {
				return true
			}
		}
	}

	if jws.Signature != "" {
		return alg.Verify(&Signature{
			Protected: jws.Protected,
			Header:    jws.Header,
			Signature: jws.Signature,
		}, []byte(jws.Payload))
	}

	return false
}

// FullHeader returns the entire header object including the protected values.
// On success, function always returns a Header and will never return nil even if both
// the protected and header values are absent.
//
// In the case of duplicate values, protected values take priority.
// The compact JWS form only has protected headers.
//
// If the protected value is not properly encoded, this function will return an error.
func (jws *JWS) FullHeader() (Header, error) {
	header := make(Header)

	if jws.Protected != "" {
		protectedData, err := base64url.Decode(jws.Protected)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(protectedData, &header)
		if err != nil {
			return nil, err
		}
	}

	if jws.Header != nil {
		for key := range jws.Header {
			if _, ok := header[key]; !ok {
				header[key] = jws.Header[key]
			}
		}
	}

	return header, nil
}
