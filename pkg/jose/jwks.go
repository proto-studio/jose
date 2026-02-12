package jose

import (
	"encoding/json"
)

// JWKS is a JSON Web Key Set: a set of JWKs used to verify JWS signatures.
type JWKS struct {
	Keys []*JWK `json:"keys" validate:"keys"`
}

// NewJWKS creates a new JWKS from a slice of JWK pointers.
func NewJWKS(jwks ...*JWK) *JWKS {
	return &JWKS{
		Keys: jwks,
	}
}

// Add appends a JWK to the JWKS.
func (j *JWKS) Add(jwk *JWK) {
	j.Keys = append(j.Keys, jwk)
}

// GetByKid searches for a JWK with the specified kid in the JWKS.
// Returns the JWK if found, otherwise returns nil.
func (j *JWKS) GetByKid(kid string) *JWK {
	for _, key := range j.Keys {
		if key.Kid == kid {
			return key
		}
	}
	return nil
}

// jsonMarshalJWKS is a hook for tests to simulate Marshal failure.
var jsonMarshalJWKS = json.Marshal

// String returns the JSON representation of the JWKS.
func (j *JWKS) String() string {
	data, err := jsonMarshalJWKS(j)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// AlgorithmsFor gets all algorithms that may be able to verify a specific header.
func (j *JWKS) AlgorithmsFor(head *Header) ([]Algorithm, error) {
	algs := make([]Algorithm, 0)

	if head != nil {
		alg, _ := (*head)["alg"].(string)
		kid, _ := (*head)["kid"].(string)

		for _, key := range j.Keys {
			if key.Kid == kid {
				alg, err := key.Algorithm(alg)
				if alg != nil && err == nil {
					algs = append(algs, alg)
				}
			}
		}
	}

	return algs, nil
}
