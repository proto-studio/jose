package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"proto.zip/studio/jose/pkg/jose"
)

// loadKeysFromSource reads key material from a file path or URL.
// Returns a slice of JWKs (one for a single JWK file, or the keys array for a JWKS file/URL).
func loadKeysFromSource(source string) ([]*jose.JWK, error) {
	var raw []byte
	var err error
	if isURL(source) {
		raw, err = fetchURL(source)
	} else {
		raw, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, err
	}
	return parseKeyMaterial(raw)
}

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func fetchURL(u string) ([]byte, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// parseKeyMaterial parses JSON as either a single JWK or a JWKS (object with "keys").
func parseKeyMaterial(raw []byte) ([]*jose.JWK, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse key material: %w", err)
	}
	if keysRaw, ok := v["keys"]; ok {
		var keys []*jose.JWK
		if err := json.Unmarshal(keysRaw, &keys); err != nil {
			return nil, fmt.Errorf("parse keys array: %w", err)
		}
		return keys, nil
	}
	// Single JWK
	var jwk jose.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}
	return []*jose.JWK{&jwk}, nil
}

// verifyWithKeys returns true if the JWS verifies with any of the given keys.
func verifyWithKeys(jws *jose.JWS, keys []*jose.JWK) bool {
	header, err := jws.FullHeader()
	if err != nil {
		return false
	}
	algName, _ := header[jose.HeaderAlg].(string)
	kid, _ := header[jose.HeaderKid].(string)
	for _, key := range keys {
		if kid != "" && key.Kid != "" && key.Kid != kid {
			continue
		}
		alg, err := key.Algorithm(algName)
		if err != nil || alg == nil {
			continue
		}
		if jws.Verify(key) {
			return true
		}
	}
	return false
}

func readStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func trimStdin(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
