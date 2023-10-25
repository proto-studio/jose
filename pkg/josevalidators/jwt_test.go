package josevalidators_test

import (
	"testing"

	"proto.zip/studio/jose/pkg/josevalidators"
)

func TestBug(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9kZW1vLmNlcnRpZmljYXRpb24ub3BlbmlkLm5ldC90ZXN0L1N3Nm1VdU0xa3BEU205dC9jYWxsYmFjayIsInN0YXRlIjoiREFRVnF6b2hLbyIsIm5vbmNlIjoiOVBwaXFiZlR0eCIsImNsaWVudF9pZCI6Ijc0ZTYyYWZlLWUyYTctNDRiMS1iZTlkLTRkOTUwMWIyNWMzMSJ9."

	jwt, err := josevalidators.NewJWT().Validate(jwtStr)

	if jwt == nil {
		t.Error("Expect JWT to not be nil")
	}

	if err != nil && len(err) == 0 {
		t.Error("Found empty error collection")
	}
}
