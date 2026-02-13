package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"proto.zip/studio/jose/internal/base64url"
	"proto.zip/studio/jose/pkg/jose"
)

func TestParseKeyMaterial_SingleJWK(t *testing.T) {
	raw := []byte(`{"kty":"oct","k":"c2VjcmV0","alg":"HS256"}`)
	keys, err := parseKeyMaterial(raw)
	if err != nil {
		t.Fatalf("parseKeyMaterial: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	if keys[0].Kty != "oct" || keys[0].Alg != "HS256" {
		t.Errorf("key = %+v", keys[0])
	}
}

func TestParseKeyMaterial_JWKS(t *testing.T) {
	raw := []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256"},{"kty":"EC","crv":"P-256","x":"x","y":"y"}]}`)
	keys, err := parseKeyMaterial(raw)
	if err != nil {
		t.Fatalf("parseKeyMaterial: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(keys))
	}
}

func TestParseKeyMaterial_InvalidJSON(t *testing.T) {
	_, err := parseKeyMaterial([]byte("not json"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadKeysFromSource_File_SingleJWK(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "jwk.json")
	if err := os.WriteFile(f, []byte(`{"kty":"oct","k":"c2VjcmV0","alg":"HS256"}`), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadKeysFromSource(f)
	if err != nil {
		t.Fatalf("loadKeysFromSource: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
}

func TestLoadKeysFromSource_File_JWKS(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "jwks.json")
	jwks := map[string]any{"keys": []map[string]any{
		{"kty": "oct", "k": "c2VjcmV0", "alg": "HS256"},
	}}
	raw, _ := json.Marshal(jwks)
	if err := os.WriteFile(f, raw, 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadKeysFromSource(f)
	if err != nil {
		t.Fatalf("loadKeysFromSource: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
}

func TestLoadKeysFromSource_URL_JWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256"}]}`))
	}))
	defer server.Close()

	keys, err := loadKeysFromSource(server.URL)
	if err != nil {
		t.Fatalf("loadKeysFromSource: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
}

func TestVerifyWithKeys_Valid(t *testing.T) {
	alg := jose.NewHS256([]byte("secret"))
	jws := &jose.JWS{Payload: base64url.Encode([]byte("payload"))}
	if err := jws.SignWithType("JWS", alg); err != nil {
		t.Fatal(err)
	}
	compact, _ := jws.Compact()
	jws2, _ := jose.ParseCompactJWS(compact)
	jwk, _ := jose.NewJWK(`{"kty":"oct","k":"c2VjcmV0","alg":"HS256"}`)
	if !verifyWithKeys(jws2, []*jose.JWK{jwk}) {
		t.Error("verifyWithKeys should succeed")
	}
}

func TestVerifyWithKeys_Invalid(t *testing.T) {
	alg := jose.NewHS256([]byte("secret"))
	jws := &jose.JWS{Payload: base64url.Encode([]byte("payload"))}
	if err := jws.SignWithType("JWS", alg); err != nil {
		t.Fatal(err)
	}
	compact, _ := jws.Compact()
	jws2, _ := jose.ParseCompactJWS(compact)
	wrongJWK, _ := jose.NewJWK(`{"kty":"oct","k":"d3Jvbmc=","alg":"HS256"}`) // "wrong"
	if verifyWithKeys(jws2, []*jose.JWK{wrongJWK}) {
		t.Error("verifyWithKeys should fail with wrong key")
	}
}

func TestIsURL(t *testing.T) {
	if !isURL("https://example.com/jwks.json") {
		t.Error("https URL should be true")
	}
	if !isURL("http://localhost/keys") {
		t.Error("http URL should be true")
	}
	if isURL("/path/to/file.json") {
		t.Error("path should be false")
	}
	if isURL("file.json") {
		t.Error("relative path should be false")
	}
}
