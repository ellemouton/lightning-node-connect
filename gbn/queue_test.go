package gbn

import (
	"sync"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

func TestQueueSize(t *testing.T) {
	q := newQueue(&queueCfg{s: 4})

	require.Equal(t, uint8(0), q.size())

	q.sequenceBase = 2
	q.sequenceTop = 3
	require.Equal(t, uint8(1), q.size())

	q.sequenceBase = 3
	q.sequenceTop = 2
	require.Equal(t, uint8(3), q.size())
}

func TestQueueResend(t *testing.T) {
	t.Parallel()

	resentPackets := make(map[uint8]struct{})
	queueTimeout := time.Second * 1

	cfg := &queueCfg{
		s:       5,
		timeout: queueTimeout,
		sendPkt: func(packet *PacketData) error {
			resentPackets[packet.Seq] = struct{}{}

			return nil
		},
	}
	q := newQueue(cfg)

	pkt1 := &PacketData{Seq: 1}
	pkt2 := &PacketData{Seq: 2}
	pkt3 := &PacketData{Seq: 3}

	q.addPacket(pkt1)

	// First test that we shouldn't resend if the timeout hasn't passed.
	q.lastResend = time.Now()

	err := q.resend()
	require.NoError(t, err)

	require.Empty(t, resentPackets)

	// Secondly, let's test that we do resend if the timeout has passed, and
	// that we then start a resend catchup once we've resent the packet.
	q.lastResend = time.Now().Add(-queueTimeout * 2)

	// Let's first test the resend catch up scenario where we don't receive
	// the expected ACK/NACK for the resent packet. This should trigger a
	// timeout of the resend catch up, which should be the
	// queueTimeout * awaitingTimeoutMultiplier.
	startTime := time.Now()

	var wg sync.WaitGroup
	resend(t, q, &wg)

	wg.Wait()

	// Check that the resend took at least the
	// queueTimeout * awaitingTimeoutMultiplier for the resend catch up to
	// complete, and that we actually resent the packet.
	require.GreaterOrEqual(
		t, time.Since(startTime),
		queueTimeout*awaitingTimeoutMultiplier,
	)
	require.Contains(t, resentPackets, pkt1.Seq)

	// Now let's test the resend catch up scenario where we do receive the
	// expected ACK for the resent packet. This should trigger a
	// queue.proceedAfterTime call, which should finish the resend catch up
	// after queueTimeout.
	q.lastResend = time.Now().Add(-queueTimeout * 2)

	q.addPacket(pkt2)

	startTime = time.Now()

	resend(t, q, &wg)

	// Simulate that we receive the expected ACK for the resent packet.
	q.processACK(pkt2.Seq)

	wg.Wait()

	// Now check that the resend took at least the queueTimeout for the
	// resend catch up to complete, and that we actually resent the packet.
	require.GreaterOrEqual(t, time.Since(startTime), queueTimeout)
	require.LessOrEqual(t, time.Since(startTime), queueTimeout*2)
	require.Contains(t, resentPackets, pkt2.Seq)

	// Finally, let's test the resend catch up scenario where we do receive
	// the expected NACK for the resent packet. This make the resend catch
	// up to complete immediately.
	q.lastResend = time.Now().Add(-queueTimeout * 2)

	q.addPacket(pkt3)

	startTime = time.Now()
	resend(t, q, &wg)

	// Simulate that we receive the expected NACK for the resent packet.
	q.processNACK(pkt3.Seq + 1)

	wg.Wait()

	// Finally let's check that we didn't await any timeout now, and that
	// we actually resent the packet.
	require.Less(t, time.Since(startTime), queueTimeout)
	require.Contains(t, resentPackets, pkt3.Seq)
}

// resend is a helper function that resends packets in a goroutine, and notifies
// the WaitGroup when the resend + resend catch up has completed.
// The function will block until the resend has actually started.
func resend(t *testing.T, q *queue, wg *sync.WaitGroup) {
	t.Helper()

	wg.Add(1)

	// This will trigger a resend catchup, so we launch the resend in a
	// goroutine.
	go func() {
		err := q.resend()
		require.NoError(t, err)

		wg.Done()
	}()

	// We also ensure that the above goroutine is has started the resend
	// before this function returns.
	err := wait.Predicate(func() bool {
		return q.syncer.getState() == syncStateWaiting
	}, time.Second)
	require.NoError(t, err)
}
