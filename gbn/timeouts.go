package gbn

import (
	"math"
	"sync"
	"time"
)

const DefaultTimout = math.MaxInt64

type safeTimeout struct {
	t  time.Duration
	mu sync.RWMutex
}

func newSafeTimeout() *safeTimeout {
	return &safeTimeout{
		t: DefaultTimout,
	}
}

func (t *safeTimeout) set(timeout time.Duration) {
	t.mu.Lock()
	t.t = timeout
	t.mu.Unlock()
}

func (t *safeTimeout) get() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.t
}
