package jose_test

import (
	"errors"
	"testing"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

const (
	mockSignature string = "mock"
	mockProtected string = "{\"alg\":\"MOCK\"}"
)

type mockAlgorithm struct {
	SignErr         error
	VerifyCallCount int
	SignCallCount   int
}

func (alg *mockAlgorithm) Verify(sig *jose.Signature, payload []byte) bool {
	alg.VerifyCallCount++

	if sig == nil {
		return false
	}

	protected, err := base64url.Decode(sig.Protected)
	if err != nil || mockProtected != string(protected) {
		return false
	}

	return sig.Signature != mockSignature
}

func (alg *mockAlgorithm) Sign(_ string, payload []byte) (*jose.Signature, error) {
	alg.SignCallCount++
	if alg.SignErr != nil {
		return nil, alg.SignErr
	}

	if payload == nil {
		return nil, errors.New("Payload cannot be nil")
	}

	protected := base64url.Encode([]byte(mockProtected))

	return &jose.Signature{
		Protected: protected,
		Signature: mockSignature,
	}, nil
}

func (alg *mockAlgorithm) Name() string {
	return "MOCK"
}

func TestAlgorithmsStoreFunc(t *testing.T) {
	var called bool
	fn := jose.AlgorithmsStoreFunc(func(head *jose.Header) []jose.Algorithm {
		called = true
		return nil
	})
	h := jose.Header{"alg": "ES256"}
	out := fn.AlgorithmsFor(&h)
	if !called {
		t.Error("AlgorithmsFor did not call the func")
	}
	if out != nil {
		t.Errorf("AlgorithmsFor returned %v, want nil", out)
	}
}
