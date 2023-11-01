package gbn

import (
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

const (
	// awaitingTimeoutMultiplier defines the multiplier we use when
	// multiplying the resend timeout during a resend catch up, resulting in
	// duration we wait for the resend catch up to complete before timing
	// out.
	// We set this to 3X the resend timeout. The reason we wait exactly 3X
	// the resend timeout is that we expect that the max time correct
	// behavior would take, would be:
	// * 1X the resendTimeout for the time it would take for the party
	// respond with an ACK for the last packet in the resend queue, i.e. the
	// awaitedACK.
	// * 1X the resendTimeout while waiting in proceedAfterTime before
	// sending the awaitedACKSignal.
	// * 1X extra resendTimeout as buffer, to ensure that we have enough
	// time to process the ACKS/NACKS by other party + some extra margin.
	awaitingTimeoutMultiplier = 3
)

type queueCfg struct {
	// s is the maximum sequence number used to label packets. Packets
	// are labelled with incrementing sequence numbers modulo s.
	// s must be strictly larger than the window size, n. This
	// is so that the receiver can tell if the sender is resending the
	// previous window (maybe the sender did not receive the acks) or if
	// they are sending the next window. If s <= n then there would be
	// no way to tell.
	s uint8

	timeout time.Duration

	log btclog.Logger

	sendPkt func(packet *PacketData) error
}

// queue is a fixed size queue with a sliding window that has a base and a top
// modulo s.
type queue struct {
	cfg *queueCfg

	// content is the current content of the queue. This is always a slice
	// of length s but can contain nil elements if the queue isn't full.
	content []*PacketData

	// sequenceBase keeps track of the base of the send window and so
	// represents the next ack that we expect from the receiver. The
	// maximum value of sequenceBase is s.
	// sequenceBase must be guarded by baseMtx.
	sequenceBase uint8

	// baseMtx is used to guard sequenceBase.
	baseMtx sync.RWMutex

	// sequenceTop is the sequence number of the latest packet.
	// The difference between sequenceTop and sequenceBase should never
	// exceed the window size, n. The maximum value of sequenceBase is s.
	// sequenceTop must be guarded by topMtx.
	sequenceTop uint8

	// topMtx is used to guard sequenceTop.
	topMtx sync.RWMutex

	// awaitedACK defines the sequence number for the last packet in the
	// resend queue. If we receive an ACK for this sequence number during
	// the resend catch up, we wait for the duration of the resend timeout,
	// and then proceed to send new packets, unless we receive the
	// awaitedNACK during the wait time. If that happens, we will proceed
	// send new packets as soon as we have processed the NACK.
	awaitedACK uint8

	// awaitedNACK defines the sequence number that in case we get a NACK
	// with that sequence number during the resend catch up, we'd consider
	// the catch up to be complete and we can proceed to send new packets.
	awaitedNACK uint8

	// awaitingCatchUp is set to true if we are awaiting a catch up after we
	// have resent the queue.
	awaitingCatchUp bool

	// awaitingCatchUpMu must be held when accessing or mutating the values
	// of awaitedACK, awaitedNACK and awaitingCatchUp.
	awaitingCatchUpMu sync.RWMutex

	// awaitedACKSignal is used to signal that we have received the awaited
	// ACK after resending the queue, and have waited for the duration of
	// the resend timeout. Once this signal is received, we can proceed to
	// send new packets.
	awaitedACKSignal chan struct{}

	// awaitedNACKSignal is used to signal that we have received the awaited
	// NACK after resending the queue. Once this signal is received, we can
	// proceed to send new packets.
	awaitedNACKSignal chan struct{}

	// caughtUpSignal is used to signal that we have caught up after
	// awaiting the catch up after resending the queue.
	caughtUpSignal chan struct{}

	lastResend time.Time

	quit chan struct{}
}

// newQueue creates a new queue.
func newQueue(cfg *queueCfg) *queue {
	if cfg.log == nil {
		cfg.log = log
	}

	return &queue{
		cfg:               cfg,
		content:           make([]*PacketData, cfg.s),
		awaitedACKSignal:  make(chan struct{}, 1),
		awaitedNACKSignal: make(chan struct{}, 1),
		caughtUpSignal:    make(chan struct{}, 1),
		quit:              make(chan struct{}),
	}
}

func (q *queue) stop() {
	close(q.quit)
}

// size is used to calculate the current sender queueSize.
func (q *queue) size() uint8 {
	q.baseMtx.RLock()
	defer q.baseMtx.RUnlock()

	q.topMtx.RLock()
	defer q.topMtx.RUnlock()

	if q.sequenceTop >= q.sequenceBase {
		return q.sequenceTop - q.sequenceBase
	}

	return q.sequenceTop + (q.cfg.s - q.sequenceBase)
}

// addPacket adds a new packet to the queue.
func (q *queue) addPacket(packet *PacketData) {
	q.topMtx.Lock()
	defer q.topMtx.Unlock()

	packet.Seq = q.sequenceTop
	q.content[q.sequenceTop] = packet
	q.sequenceTop = (q.sequenceTop + 1) % q.cfg.s
}

// resend resends the current contents of the queue, by invoking the callback
// for each packet that needs to be resent, and then awaits that we either
// receive the expected ACK or NACK after resending the queue, before returning.
//
// To understand why we need to await the awaited ACK/NACK after resending the
// queue, it ensures that we don't end up in a situation where we resend the
// queue over and over again due to latency and delayed NACKs by the other
// party.
//
// Consider the following scenario:
// 1.
// Alice sends packets 1, 2, 3 & 4 to Bob.
// 2.
// Bob receives packets 1, 2, 3 & 4, and sends back the respective ACKs.
// 3.
// Alice receives ACKs for packets 1 & 2, but due to latency the ACKs for
// packets 3 & 4 are delayed and aren't received until Alice resend timeout
// has passed, which leads to Alice resending packets 3 & 4. Alice will after
// that receive the delayed ACKs for packets 3 & 4, but will consider that as
// the ACKs for the resent packets, and not the original packets which they were
// actually sent for. If we didn't wait after resending the queue, Alice would
// then proceed to send more packets (5 & 6).
// 4.
// When Bob receives the resent packets 3 & 4, Bob will respond with NACK 5. Due
// to latency, the packets 5 & 6 that Alice sent in step (3) above will then be
// received by Bob, and be processed as the correct response to the NACK 5. Bob
// will after that await packet 7.
// 5.
// Alice will receive the NACK 5, and now resend packets 5 & 6. But as Bob is
// now awaiting packet 7, this send will lead to a NACK 7. But due to latency,
// if Alice doesn't wait resending the queue, Alice will proceed to send new
// packet(s) before receiving the NACK 7.
// 6.
// This resend loop would continue indefinitely, so we need to ensure that Alice
// waits after she has resent the queue, to ensure that she doesn't proceed to
// send new packets before she is sure that both parties are in sync.
//
// To ensure that we are in sync, after we have resent the queue, we will await
// that we either:
// 1. Receive a NACK for the sequence number succeeding the last packet in the
// resent queue i.e. in step (3) above, that would be NACK 5.
// OR
// 2. Receive an ACK for the last packet in the resent queue i.e. in step (3)
// above, that would be ACK 4. After we receive the expected ACK, we will then
// wait for the duration of the resend timeout before continuing. The reason why
// we wait for the resend timeout before continuing, is that the ACKs we are
// getting after a resend, could be delayed ACKs for the original packets we
// sent, and not ACKs for the resent packets. In step (3) above, the ACKs for
// packets 3 & 4 that Alice received were delayed ACKs for the original packets.
// If Alice would have immediately continued to send new packets (5 & 6) after
// receiving the ACK 4, she would have then received the NACK 5 from Bob which
// was the actual response to the resent queue. But as Alice had already
// continued to send packets 5 & 6 when receiving the NACK 5, the resend queue
// response to that NACK would cause the resend loop to continue indefinitely.
//
// When either of the 2 conditions above are met, we will consider both parties
// to be in sync, and we can proceed to send new packets.
func (q *queue) resend() error {
	if time.Since(q.lastResend) < q.cfg.timeout {
		q.cfg.log.Tracef("Resent the queue recently.")

		return nil
	}

	if q.size() == 0 {
		return nil
	}

	q.lastResend = time.Now()

	q.awaitingCatchUpMu.Lock()

	q.baseMtx.RLock()
	base := q.sequenceBase
	q.baseMtx.RUnlock()

	q.topMtx.RLock()
	top := q.sequenceTop
	q.topMtx.RUnlock()

	if base == top {
		q.awaitingCatchUpMu.Unlock()

		return nil
	}

	// Prepare the queue for awaiting the resend catch up.
	q.awaitedACK = (q.cfg.s + top - 1) % q.cfg.s
	q.awaitedNACK = top

	q.cfg.log.Tracef("Set awaitedACK to %d & awaitedNACK to %d",
		q.awaitedACK, q.awaitedNACK)

	q.awaitingCatchUp = true

	// Drain the caughtUpSignal channel, in case no proceedAfterTime
	// func was executed after the last resend catch up.
	select {
	case <-q.caughtUpSignal:
	default:
	}

	q.cfg.log.Tracef("Resending the queue")

	for base != top {
		packet := q.content[base]

		if err := q.cfg.sendPkt(packet); err != nil {
			q.awaitingCatchUpMu.Unlock()

			return err
		}

		base = (base + 1) % q.cfg.s

		q.cfg.log.Tracef("Resent %d", packet.Seq)
	}

	// We hold the awaitingCatchUpMu mutex for the duration of the resend to
	// ensure that we don't process the delayed ACKs for the packets we are
	// resending, during the resend. If that would happen, we would start
	// the "proceedAfterTime" function timeout while still resending
	// packets. That could mean that the NACK that the resent packets will
	// trigger, might be received after the timeout has passed. That would
	// cause the resend loop to trigger once more.
	q.awaitingCatchUpMu.Unlock()

	// Then await until we know that both parties are in sync.
	q.awaitCatchUp()

	return nil
}

// awaitCatchUp awaits that we either receive the awaited ACK or NACK signal
// before returning. If we don't receive the awaited ACK or NACK signal before
// 3X the resend timeout, the function will also return.
// See the docs for the resend function for more details on why we need to await
// the awaited ACK or NACK signal.
func (q *queue) awaitCatchUp() {
	q.cfg.log.Tracef("Awaiting catchup after resending the queue")

	select {
	case <-q.quit:
		return
	case <-q.awaitedACKSignal:
		q.cfg.log.Tracef("Got awaitedACKSignal")
	case <-q.awaitedNACKSignal:
		q.cfg.log.Tracef("Got awaitedNACKSignal")
	case <-time.After(q.cfg.timeout * awaitingTimeoutMultiplier):
		q.cfg.log.Tracef("Timed out while awaiting catchup")

		q.awaitingCatchUpMu.Lock()
		q.awaitingCatchUp = false

		// Drain both the ACK & NACK signal channels.
		select {
		case <-q.awaitedACKSignal:
		default:
		}

		select {
		case <-q.awaitedNACKSignal:
		default:
		}

		q.awaitingCatchUpMu.Unlock()
	}

	// Send a caughtUpSignal to indicate that we have caught up after
	// resending the queue.
	q.caughtUpSignal <- struct{}{}
}

// processACK processes an incoming ACK of a given sequence number.
func (q *queue) processACK(seq uint8) bool {
	// If our queue is empty, an ACK should not have any effect.
	if q.size() == 0 {
		q.cfg.log.Tracef("Received ack %d, but queue is empty. "+
			"Ignoring.", seq)

		return false
	}

	// If we are awaiting a catch up, and the ACK is the awaited ACK, we
	// start the proceedAfterTime function in a goroutine, which will send
	// an awaitedACKSignal if we're still awaiting the resend catch up when
	// the resend timeout has expired.
	q.awaitingCatchUpMu.RLock()
	if seq == q.awaitedACK && q.awaitingCatchUp {
		q.cfg.log.Tracef("Got awaited ACK")

		// We start the proceedAfterTime function in a goroutine, as we
		// don't want to block the processing of other NACKs/ACKs while
		// we're waiting for the resend timeout to expire.
		go q.proceedAfterTime()
	}
	q.awaitingCatchUpMu.RUnlock()

	q.baseMtx.Lock()
	defer q.baseMtx.Unlock()

	if seq == q.sequenceBase {
		// We received an ACK packet with the sequence number that is
		// equal to the one we were expecting. So we increase our base
		// accordingly and send a signal to indicate that the queue size
		// has decreased.
		q.cfg.log.Tracef("Received correct ack %d", seq)

		q.sequenceBase = (q.sequenceBase + 1) % q.cfg.s

		// We did receive an ACK.
		return true
	}

	// We received an ACK with a sequence number that we were not expecting.
	// This could be a duplicate ACK before or it could be that we just
	// missed the ACK for the current base and this is actually an ACK for
	// another packet in the queue.
	q.cfg.log.Tracef("Received wrong ack %d, expected %d", seq,
		q.sequenceBase)

	q.topMtx.RLock()
	defer q.topMtx.RUnlock()

	// If this is an ACK for something in the current queue then maybe we
	// just missed a previous ACK. We can bump the base to be equal to this
	// sequence number.
	if containsSequence(q.sequenceBase, q.sequenceTop, seq) {
		q.cfg.log.Tracef("Sequence %d is in the queue. Bump the base.",
			seq)

		q.sequenceBase = (seq + 1) % q.cfg.s

		// We did receive an ACK.
		return true
	}

	// We didn't receive a valid ACK for anything in our queue.
	return false
}

// processNACK processes an incoming NACK of a given sequence number.
func (q *queue) processNACK(seq uint8) (bool, bool) {
	q.awaitingCatchUpMu.Lock()
	defer q.awaitingCatchUpMu.Unlock()

	q.baseMtx.Lock()
	defer q.baseMtx.Unlock()

	q.topMtx.RLock()
	defer q.topMtx.RUnlock()

	q.cfg.log.Tracef("Received NACK %d", seq)

	if q.awaitingCatchUp && seq == q.awaitedNACK {
		q.cfg.log.Tracef("Sending awaitedNACKSignal")
		q.awaitedNACKSignal <- struct{}{}

		q.awaitingCatchUp = false

		// In case the awaitedNACK is the same as sequenceTop, we can
		// bump the base to be equal to sequenceTop, without triggering
		// a new resend.
		if seq == q.sequenceTop {
			q.sequenceBase = q.sequenceTop
		}

		// If we receive the awaited NACK, we shouldn't trigger a new
		// resend, as we can now proceed to send new packets.
		return false, false
	}

	// If the NACK is the same as sequenceTop, and we weren't awaiting this
	// NACK as part of the resend catch up, it probably means that queue
	// was sent successfully, but we just missed the necessary ACKs. So we
	// can empty the queue here by bumping the base and we don't need to
	// trigger a resend.
	if seq == q.sequenceTop {
		q.sequenceBase = q.sequenceTop

		return false, false
	}

	// Is the NACKed sequence even in our queue?
	if !containsSequence(q.sequenceBase, q.sequenceTop, seq) {
		q.cfg.log.Tracef("NACK seq %d is not in the queue. Ignoring.",
			seq)

		return false, false
	}

	// The NACK sequence is in the queue. So we bump the
	// base to be whatever the sequence is.
	bumped := false
	if q.sequenceBase != seq {
		bumped = true
	}

	q.sequenceBase = seq

	return true, bumped
}

// proceedAfterTime will wait for the resendTimeout and then send an
// awaitedACKSignal, if we're still awaiting the resend catch up.
func (q *queue) proceedAfterTime() {
	// We await for the duration of the resendTimeout before sending the
	// awaitedACKSignal, as that's the time we'd expect it to take for the
	// other party to respond with a NACK, if the resent last packet in the
	// queue would lead to a NACK. If we receive the awaitedNACKSignal
	// before the timeout, we will receive the caughtUpSignal, and we can
	// stop the execution early.
	select {
	case <-q.quit:
		return
	case <-q.caughtUpSignal:
		q.cfg.log.Tracef("Already caught up.")

		return
	case <-time.After(q.cfg.timeout):
		q.awaitingCatchUpMu.Lock()

		if q.awaitingCatchUp {
			q.cfg.log.Tracef("Sending awaitedACKSignal")
			q.awaitedACKSignal <- struct{}{}

			q.awaitingCatchUp = false
		} else {
			q.cfg.log.Tracef("Ending proceedAfterTime without any " +
				"action")
		}

		q.awaitingCatchUpMu.Unlock()
	}
}

// containsSequence is used to determine if a number, seq, is between two other
// numbers, base and top, where all the numbers lie in a finite field (modulo
// space) s.
func containsSequence(base, top, seq uint8) bool {
	// If base and top are equal then the queue is empty.
	if base == top {
		return false
	}

	if base < top {
		if base <= seq && seq < top {
			return true
		}
		return false
	}

	// top < base
	if seq < top || base <= seq {
		return true
	}

	return false
}
