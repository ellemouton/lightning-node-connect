package gbn

import (
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

const (
	awaitingTimeoutMultiplier = 3
)

type syncState uint8

const (
	syncStateIdle syncState = iota
	syncStateResending
	syncStateWaiting
)

type syncer struct {
	s       uint8
	log     btclog.Logger
	timeout time.Duration

	state syncState

	awaitedACK  uint8
	awaitedNACK uint8

	cancel chan struct{}

	quit chan struct{}
	mu   sync.Mutex
}

func newSyncer(s uint8, log btclog.Logger, timeout time.Duration,
	quit chan struct{}) *syncer {

	return &syncer{
		s:       s,
		log:     log,
		timeout: timeout,
		state:   syncStateIdle,
		cancel:  make(chan struct{}),
		quit:    quit,
	}
}

func (c *syncer) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.resetUnsafe()
}

func (c *syncer) resetUnsafe() {
	c.state = syncStateIdle

	// Cancel any pending sync.
	select {
	case c.cancel <- struct{}{}:
	default:
	}
}

func (c *syncer) initResend() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != syncStateIdle {
		return false
	}

	c.state = syncStateResending

	return true
}

func (c *syncer) resendingUpTo(top uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.awaitedACK = (c.s + top - 1) % c.s
	c.awaitedNACK = top

	c.log.Tracef("Set awaitedACK to %d & awaitedNACK to %d",
		c.awaitedACK, c.awaitedNACK)

}

func (c *syncer) getState() syncState {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.state
}

func (c *syncer) waitForSync() {
	c.log.Tracef("Awaiting sync after resending the queue")

	c.mu.Lock()
	c.state = syncStateWaiting
	c.mu.Unlock()

	select {
	case <-c.quit:
		return

	case <-c.cancel:
		c.log.Tracef("sync canceled or reset")

	case <-time.After(c.timeout * awaitingTimeoutMultiplier):
		c.log.Tracef("Timed out while waiting for sync")
	}

	c.reset()
}

func (c *syncer) processAck(seq uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If we are not waiting after a resend, just swallow the ACK.
	if c.state != syncStateWaiting {
		return
	}

	// Else, if we are waiting but this is not the ack we are waiting for,
	// just swallow it.
	if seq != c.awaitedACK {
		return
	}

	c.log.Tracef("Got awaited ACK")

	// We start the proceedAfterTime function in a goroutine, as we
	// don't want to block the processing of other NACKs/ACKs while
	// we're waiting for the resend timeout to expire.
	go c.proceedAfterTime()
}

func (c *syncer) processNack(seq uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If we are not waiting after a resend, just swallow the NACK.
	if c.state != syncStateWaiting {
		return
	}

	// Else, if we are waiting but this is not the NACK we are waiting for,
	// just swallow it.
	if seq != c.awaitedNACK {
		return
	}

	c.log.Tracef("Sending awaitedNACKSignal")

	c.resetUnsafe()
}

// proceedAfterTime will wait for the resendTimeout and then send an
// awaitedACKSignal, if we're still awaiting the resend catch up.
func (c *syncer) proceedAfterTime() {
	// We await for the duration of the resendTimeout before sending the
	// awaitedACKSignal, as that's the time we'd expect it to take for the
	// other party to respond with a NACK, if the resent last packet in the
	// queue would lead to a NACK. If we receive the awaitedNACKSignal
	// before the timeout, we will receive the caughtUpSignal, and we can
	// stop the execution early.
	select {
	case <-c.quit:
		return

	case <-c.cancel:
		c.log.Tracef("sync succeeded or was reset")

		return

	case <-time.After(c.timeout):
		c.mu.Lock()
		defer c.mu.Unlock()

		if c.state != syncStateWaiting {
			return
		}

		c.resetUnsafe()
	}
}
