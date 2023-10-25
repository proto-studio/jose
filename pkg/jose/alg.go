package jose

type Algorithm interface {
	Verify(sig *Signature, payload []byte) bool
	Sign(typ string, payload []byte) (*Signature, error)
	Name() string
}

type AlgorithmStore interface {
	AlgorithmsFor(head *Header) []Algorithm
}

type AlgorithmsStoreFunc func(head *Header) []Algorithm

func (fn AlgorithmsStoreFunc) AlgorithmsFor(head *Header) []Algorithm {
	return fn(head)
}
