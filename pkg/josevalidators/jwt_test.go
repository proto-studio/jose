package josevalidators_test

import (
	"context"
	"testing"

	"proto.zip/studio/jose/pkg/jose"
	"proto.zip/studio/jose/pkg/josevalidators"
)

func TestBug(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9kZW1vLmNlcnRpZmljYXRpb24ub3BlbmlkLm5ldC90ZXN0L1N3Nm1VdU0xa3BEU205dC9jYWxsYmFjayIsInN0YXRlIjoiREFRVnF6b2hLbyIsIm5vbmNlIjoiOVBwaXFiZlR0eCIsImNsaWVudF9pZCI6Ijc0ZTYyYWZlLWUyYTctNDRiMS1iZTlkLTRkOTUwMWIyNWMzMSJ9."

	var jwt *jose.JWT
	err := josevalidators.JWT().Apply(context.Background(), jwtStr, &jwt)

	if jwt == nil {
		t.Error("Expect JWT to not be nil")
	}

	if err != nil && len(err) == 0 {
		t.Error("Found empty error collection")
	}
}

func TestJWTOutputTypes(t *testing.T) {
	jwtStr := "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9."

	t.Run("any output", func(t *testing.T) {
		var output any
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
	})

	t.Run("*jose.JWT output", func(t *testing.T) {
		var output jose.JWT
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output.Claims == nil {
			t.Error("Expected JWT claims to not be nil")
		}
	})

	t.Run("**jose.JWT output", func(t *testing.T) {
		var output *jose.JWT
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
		if output.Claims == nil {
			t.Error("Expected JWT claims to not be nil")
		}
	})

	t.Run("jose.JWS output", func(t *testing.T) {
		var output jose.JWS
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output.Payload == "" {
			t.Error("Expected JWS payload to not be empty")
		}
	})

	t.Run("*jose.JWS output", func(t *testing.T) {
		var output *jose.JWS
		err := josevalidators.JWT().Apply(context.Background(), jwtStr, &output)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if output == nil {
			t.Error("Expected output to not be nil")
		}
		if output.Payload == "" {
			t.Error("Expected JWS payload to not be empty")
		}
	})
}
