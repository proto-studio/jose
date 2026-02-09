package base64url

import (
	"testing"
)

func TestEncode(t *testing.T) {
	out := Encode([]byte("hello"))
	if out == "" {
		t.Fatal("Encode returned empty")
	}
	dec, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(dec) != "hello" {
		t.Errorf("Decode(Encode(x)) = %q", dec)
	}
}

func TestDecode(t *testing.T) {
	// No padding
	dec, err := Decode("aGVsbG8")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(dec) != "hello" {
		t.Errorf("Decode = %q", dec)
	}
	// With padding
	dec, err = Decode("YQ==")
	if err != nil {
		t.Fatalf("Decode padded: %v", err)
	}
	if len(dec) != 1 || dec[0] != 'a' {
		t.Errorf("Decode padded = %v", dec)
	}
	// Invalid
	_, err = Decode("!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64url")
	}
}
