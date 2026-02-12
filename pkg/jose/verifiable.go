package jose

// Verifiable is implemented by types that can be verified with a JWK (e.g. JWS).
type Verifiable interface {
	Verify(jwt *JWK) bool
}
