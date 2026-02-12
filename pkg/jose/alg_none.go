package jose

import (
	"sync/atomic"
)

var noneEnabled int32

// EnableNone allows parsing and producing JWTs/JWS with no signature ("alg":"none"). Unsigned tokens are insecure; use only when required.
func EnableNone() {
	atomic.StoreInt32(&noneEnabled, 1)
}

// DisableNone disallows "alg":"none"; parsing or compacting an unsigned JWS will error.
func DisableNone() {
	atomic.StoreInt32(&noneEnabled, 0)
}

// None returns true if "alg":"none" is currently allowed.
func None() bool {
	return atomic.LoadInt32(&noneEnabled) == 1
}
