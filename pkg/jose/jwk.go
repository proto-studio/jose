package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"proto.zip/studio/jose/internal/base64url"
)

// JWK is a partial implementation of the JWK standard.
// See: https://datatracker.ietf.org/doc/html/rfc7517
type JWK struct {
	Alg string `json:"alg,omitempty" validate:"alg"` // Alg (Algorithm) specifies the algorithm intended for use with the key (e.g., "RS256" for RSA Signature with SHA-256).
	Use string `json:"use,omitempty" validate:"use"` // Use specifies how the key is intended to be used. Common values are "sig" (signature) or "enc" (encryption).
	Kty string `json:"kty,omitempty" validate:"kty"` // Kty (Key Type) defines the cryptographic algorithm family used with the key, e.g., "EC" for Elliptic Curve or "RSA" for RSA encryption.
	Crv string `json:"crv,omitempty" validate:"crv"` // Crv (Curve) defines the cryptographic curve used with the key. Relevant for elliptic curve keys (e.g., "P-256").
	Kid string `json:"kid,omitempty" validate:"kid"` // Kid (Key ID) is an optional identifier for the key, which can be used to match a specific key from a JWK Set.
	X   string `json:"x,omitempty" validate:"x"`     // X is the x-coordinate for elliptic curve keys.
	Y   string `json:"y,omitempty" validate:"y"`     // Y is the y-coordinate for elliptic curve keys.
	D   string `json:"d,omitempty" validate:"d"`     // D is the ECC private key value.
	N   string `json:"n,omitempty" validate:"n"`     // N is the modulus for RSA keys.
	E   string `json:"e,omitempty" validate:"e"`     // E is the public exponent for RSA keys.
}

func NewJWK(data interface{}) (*JWK, error) {
	switch v := data.(type) {
	case string:
		return newJWKFromJSON(v)
	case *ecdsa.PublicKey:
		return newJWKFromECDSAPublicKey(v)
	case ecdsa.PublicKey:
		return newJWKFromECDSAPublicKey(&v)
	case *ecdsa.PrivateKey:
		return newJWKFromECDSAPrivateKey(v)
	case ecdsa.PrivateKey:
		return newJWKFromECDSAPrivateKey(&v)
	case *rsa.PublicKey, rsa.PublicKey:
		return newJWKFromRSAPublicKey(v)
	case *rsa.PrivateKey:
		return newJWKFromRSAPublicKey(v.PublicKey)
	case rsa.PrivateKey:
		return newJWKFromRSAPublicKey(v.PublicKey)
	case *JWK:
		return v.Clone(), nil
	case JWK:
		return v.Clone(), nil
	default:
		return nil, errors.New("unsupported type for JWK")
	}
}

func newJWKFromJSON(jsonData string) (*JWK, error) {
	var jwk JWK
	err := json.Unmarshal([]byte(jsonData), &jwk)
	if err != nil {
		return nil, err
	}
	return &jwk, nil
}

// getJWKCrv returns the JWK crv string for a given ECDSA public key.
func getJWKCrv(publicKey *ecdsa.PublicKey) (string, error) {
	switch publicKey.Curve {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("unsupported curve")
	}
}

func newJWKFromECDSAPublicKey(ecdsaPubKey *ecdsa.PublicKey) (*JWK, error) {
	crv, err := getJWKCrv(ecdsaPubKey)
	if err != nil {
		return nil, err
	}

	jwk := &JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64url.Encode(ecdsaPubKey.X.Bytes()),
		Y:   base64url.Encode(ecdsaPubKey.Y.Bytes()),
	}
	return jwk, nil
}

func newJWKFromECDSAPrivateKey(ecdsaPrivKey *ecdsa.PrivateKey) (*JWK, error) {
	crv, err := getJWKCrv(&ecdsaPrivKey.PublicKey)
	if err != nil {
		return nil, err
	}

	jwk := &JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64url.Encode(ecdsaPrivKey.X.Bytes()),
		Y:   base64url.Encode(ecdsaPrivKey.Y.Bytes()),
		D:   base64url.Encode(ecdsaPrivKey.D.Bytes()),
	}
	return jwk, nil
}

func newJWKFromRSAPublicKey(pubKey interface{}) (*JWK, error) {
	var rsaPubKey *rsa.PublicKey
	switch v := pubKey.(type) {
	case *rsa.PublicKey:
		rsaPubKey = v
	case rsa.PublicKey:
		rsaPubKey = &v
	default:
		return nil, errors.New("invalid RSA public key type")
	}

	jwk := &JWK{
		Kty: "RSA",
		N:   base64url.Encode(rsaPubKey.N.Bytes()),
		E:   base64url.Encode(big.NewInt(int64(rsaPubKey.E)).Bytes()),
	}
	return jwk, nil
}

func (j *JWK) String() string {
	data, err := json.Marshal(j)
	if err != nil {
		return "{}" // or you can handle this differently
	}
	return string(data)
}

func (original *JWK) Clone() *JWK {
	return &JWK{
		Kty: original.Kty,
		Crv: original.Crv,
		X:   original.X,
		Y:   original.Y,
		N:   original.N,
		E:   original.E,
	}
}

// getRSAKeys extracts RSA keys from the JWK struct.
func (j *JWK) getRSAKeys() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	if j.Kty != "RSA" {
		return nil, nil, errors.New("JWK is not an RSA key")
	}

	n, err := base64url.Decode(j.N)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode modulus: %v", err)
	}

	e, err := base64url.Decode(j.E)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}

	var privateKey *rsa.PrivateKey
	if j.D != "" {
		d, err := base64url.Decode(j.D)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode private exponent: %v", err)
		}

		privateKey = &rsa.PrivateKey{
			PublicKey: *publicKey,
			D:         new(big.Int).SetBytes(d),
		}
	}

	return publicKey, privateKey, nil
}

// getCurve returns the elliptic.Curve based on the "crv" parameter of the JWK.
func getCurve(crv string) elliptic.Curve {
	switch crv {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

// getECDSAKey extracts ECDSA keys from the JWK struct.
func (j *JWK) getECDSAKeys() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	if j.Kty != "EC" {
		return nil, nil, errors.New("JWK is not an EC key")
	}

	curve := getCurve(j.Crv)
	if curve == nil {
		return nil, nil, fmt.Errorf("unsupported elliptic curve: %s", j.Crv)
	}

	x, err := base64url.Decode(j.X)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode X: %v", err)
	}

	y, err := base64url.Decode(j.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Y: %v", err)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	var privateKey *ecdsa.PrivateKey
	if j.D != "" {
		d, err := base64url.Decode(j.D)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode D: %v", err)
		}

		privateKey = &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         new(big.Int).SetBytes(d),
		}
	}

	return publicKey, privateKey, nil
}

// algorithmRSA returns the RSA algorithm for the JWK
func (j *JWK) algorithmRSA(alg string) (Algorithm, error) {
	pub, priv, err := j.getRSAKeys()
	if err != nil {
		return nil, err
	}

	switch alg {
	case "RS256":
		return NewRS256(pub, priv), nil
	case "RS384":
		return NewRS384(pub, priv), nil
	case "RS512":
		return NewRS512(pub, priv), nil
	}

	return nil, fmt.Errorf("Unknown RSA algorithm: %s", alg)
}

// algorithmRSA returns the ECDSA algorithm for the JWK
func (j *JWK) algorithmEC(alg string) (Algorithm, error) {
	pub, priv, err := j.getECDSAKeys()
	if err != nil {
		return nil, err
	}

	switch alg {
	case "ES256":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("Incompatible curve, expected P-256, got %s", j.Crv)
		}
		return NewES256(pub, priv), nil
	case "ES384":
		if j.Crv != "P-384" {
			return nil, fmt.Errorf("Incompatible curve, expected P-384, got %s", j.Crv)
		}
		return NewES384(pub, priv), nil
	case "ES512":
		if j.Crv != "P-521" {
			return nil, fmt.Errorf("Incompatible curve, expected P-521, got %s", j.Crv)
		}
		return NewES512(pub, priv), nil
	}

	return nil, fmt.Errorf("Unknown RSA algorithm: %s", alg)

}

// Algorithm returns an algorithm for the specific key if the key is compatible.
// It does not enforce any hints (such as the Alg value).
//
// Depending on jow the JWK is created, the resulting algorithm may be able to verify but not sign.
func (j *JWK) Algorithm(alg string) (Algorithm, error) {
	switch alg {
	case "RS256", "RS384", "RS512":
		return j.algorithmRSA(alg)
	case "ES256", "ES384", "ES512":
		return j.algorithmEC(alg)
	}
	return nil, fmt.Errorf("Unsupported algorithm")
}
