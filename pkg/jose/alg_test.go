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

func (alg *mockAlgorithm) Name() (string, error) {
	return "MOCK", nil
}

// TestAlgorithmsStoreFunc tests that AlgorithmsStoreFunc calls the wrapped function and returns its result.
func TestAlgorithmsStoreFunc(t *testing.T) {
	var called bool
	fn := jose.AlgorithmsStoreFunc(func(head *jose.Header) ([]jose.Algorithm, error) {
		called = true
		return nil, nil
	})
	h := jose.Header{"alg": "ES256"}
	out, err := fn.AlgorithmsFor(&h)
	if err != nil {
		t.Fatalf("AlgorithmsFor: %v", err)
	}
	if !called {
		t.Error("AlgorithmsFor did not call the func")
	}
	if out != nil {
		t.Errorf("AlgorithmsFor returned %v, want nil", out)
	}
}
