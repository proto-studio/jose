package jose

import (
	"sync/atomic"
)

var noneEnabled int32

func EnableNone() {
	atomic.StoreInt32(&noneEnabled, 1)
}

func DisableNone() {
	atomic.StoreInt32(&noneEnabled, 0)
}

func None() bool {
	return atomic.LoadInt32(&noneEnabled) == 1
}
