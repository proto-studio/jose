package josevalidators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"proto.zip/studio/jose/pkg/jose"
)

const minJWKSCacheTTL = 10 * time.Second

type jwksCacheEntry struct {
	jwks         *jose.JWKS
	fetchedAt    time.Time
	etag         string
	lastModified string
	maxAge       time.Duration // from Cache-Control max-age; 0 means not set
}

var globalJWKSCache = struct {
	sync.RWMutex
	entries map[string]*jwksCacheEntry
}{
	entries: make(map[string]*jwksCacheEntry),
}

// cacheFresh returns true if the entry should be used without revalidation (min TTL and optional max-age).
func (e *jwksCacheEntry) cacheFresh(now time.Time) bool {
	age := now.Sub(e.fetchedAt)
	if age < minJWKSCacheTTL {
		return true
	}
	if e.maxAge > 0 && age < e.maxAge {
		return true
	}
	return false
}

// getJWKSFromURL returns a JWKS from the given URL, using a global cache shared by all validators.
// Caching uses HTTP cache headers: ETag and Last-Modified are sent on revalidation (If-None-Match,
// If-Modified-Since), and 304 Not Modified is handled by reusing the cached JWKS. Cache-Control
// max-age from the response is respected. A minimum TTL of 10 seconds is enforced to prevent abuse.
func getJWKSFromURL(ctx context.Context, url string) (*jose.JWKS, error) {
	now := time.Now()

	globalJWKSCache.RLock()
	entry := globalJWKSCache.entries[url]
	globalJWKSCache.RUnlock()

	if entry != nil && entry.cacheFresh(now) {
		return entry.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Conditional request when we have cached validators
	if entry != nil {
		if entry.etag != "" {
			req.Header.Set("If-None-Match", entry.etag)
		}
		if entry.lastModified != "" {
			req.Header.Set("If-Modified-Since", entry.lastModified)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		// Reuse cached JWKS; update fetchedAt so we get another fresh window
		globalJWKSCache.Lock()
		entry = globalJWKSCache.entries[url]
		if entry != nil {
			entry.fetchedAt = now
			jwks := entry.jwks
			globalJWKSCache.Unlock()
			return jwks, nil
		}
		globalJWKSCache.Unlock()
		// Cache was cleared between read and 304; do a full GET without conditional headers
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return nil, &httpError{status: resp2.StatusCode}
		}
		var jwks jose.JWKS
		if err := json.NewDecoder(resp2.Body).Decode(&jwks); err != nil {
			return nil, err
		}
		etag := strings.Trim(resp2.Header.Get("ETag"), "\"")
		lastModified := resp2.Header.Get("Last-Modified")
		maxAge := parseCacheControlMaxAge(resp2.Header.Get("Cache-Control"))
		newEntry := &jwksCacheEntry{jwks: &jwks, fetchedAt: time.Now(), etag: etag, lastModified: lastModified, maxAge: maxAge}
		globalJWKSCache.Lock()
		globalJWKSCache.entries[url] = newEntry
		globalJWKSCache.Unlock()
		return newEntry.jwks, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{status: resp.StatusCode}
	}

	var jwks jose.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	etag := strings.Trim(resp.Header.Get("ETag"), "\"")
	lastModified := resp.Header.Get("Last-Modified")
	maxAge := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))

	newEntry := &jwksCacheEntry{
		jwks:         &jwks,
		fetchedAt:    now,
		etag:         etag,
		lastModified: lastModified,
		maxAge:       maxAge,
	}
	globalJWKSCache.Lock()
	globalJWKSCache.entries[url] = newEntry
	globalJWKSCache.Unlock()

	return newEntry.jwks, nil
}

// parseCacheControlMaxAge parses the max-age directive from a Cache-Control header value.
// Returns 0 if missing or invalid.
func parseCacheControlMaxAge(cacheControl string) time.Duration {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			s := part[8:]
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 {
				return time.Duration(n) * time.Second
			}
			return 0
		}
	}
	return 0
}

type httpError struct {
	status int
}

func (e *httpError) Error() string {
	return fmt.Sprintf("jwks url returned status %d", e.status)
}

// clearJWKSCacheForTest removes all entries from the global JWKS cache.
// It is intended for use in tests only (e.g. to isolate tests or to verify cache behavior).
func clearJWKSCacheForTest() {
	globalJWKSCache.Lock()
	globalJWKSCache.entries = make(map[string]*jwksCacheEntry)
	globalJWKSCache.Unlock()
}
