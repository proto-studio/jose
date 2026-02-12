package jose

// Algorithm is implemented by values that can sign payloads and verify signatures (e.g. RSA, ECDSA, HMAC).
type Algorithm interface {
	Verify(sig *Signature, payload []byte) bool
	Sign(typ string, payload []byte) (*Signature, error)
	Name() (string, error)
}

// AlgorithmStore returns algorithms that may verify a given JWS header (e.g. by alg and kid).
type AlgorithmStore interface {
	AlgorithmsFor(head *Header) ([]Algorithm, error)
}

// AlgorithmsStoreFunc adapts a function to the AlgorithmStore interface.
type AlgorithmsStoreFunc func(head *Header) ([]Algorithm, error)

// AlgorithmsFor calls the underlying function with head and returns its result.
func (fn AlgorithmsStoreFunc) AlgorithmsFor(head *Header) ([]Algorithm, error) {
	return fn(head)
}
