package jose

type Verifiable interface {
	Verify(jwt *JWK) bool
}
