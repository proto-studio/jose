package base64url

import (
	"encoding/base64"
	"strings"
)

func Decode(data string) ([]byte, error) {
	// Add padding if necessary
	if len(data)%4 != 0 {
		data += strings.Repeat("=", 4-len(data)%4)
	}
	return base64.URLEncoding.DecodeString(data)
}

func Encode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}
