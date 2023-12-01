package gbn

import (
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

type Sender interface {
	Send([]byte) error
	ACK(uint8)
	NACK(uint8)
	SetTimeout(time.Duration)
	AnyReceive()
}

// sender is only concerned with sending DATA packets, and handling received
// ACK and NACK packets.
type sender struct {
	// n is the window size. The sender can send a maximum of n packets
	// before requiring an ack from the receiver for the first packet in
	// the window.
	n uint8

	timeout *safeTimeout

	sendQueue *queue

	sendFn func(Message) error

	log btclog.Logger

	resendTicker  *time.Ticker
	resendTimeout time.Duration

	pingTicker   *IntervalAwareForceTicker
	pingTickerMu sync.Mutex
	pongTicker   *IntervalAwareForceTicker

	pingTime time.Duration
	pongTime time.Duration

	// maxChunkSize is the maximum payload size in bytes allowed per
	// message. If the payload to be sent is larger than maxChunkSize then
	// the payload will be split between multiple packets.
	// If maxChunkSize is zero then it is disabled and data won't be split
	// between packets.
	maxChunkSize int

	newData  chan *PacketData
	ackChan  chan uint8
	nackChan chan uint8

	// receivedACKSignal channel is used to signal that the queue size has
	// potentially been decreased.
	receivedACKSignal chan struct{}

	// resendSignal is used to signal that normal operation sending should
	// stop and the current queue contents should first be resent. Note
	// that this channel should only be listened on in one place.
	resendSignal chan struct{}

	quit    chan struct{}
	wg      sync.WaitGroup
	errChan chan error
}

func (s *sender) AnyReceive() {
	select {
	case <-s.quit:
		return
	default:
	}

	// Reset the ping & pong timer if any packet is received.
	// If ping/pong is disabled, this is a no-op.
	s.pingTickerMu.Lock()
	s.pingTicker.Reset()
	if s.pongTicker.IsActive() {
		s.pongTicker.Pause()
	}
	s.pingTickerMu.Unlock()
}

func newSender(n uint8, sendFn func(Message) error, errChan chan error,
	logger btclog.Logger, resendTimeout time.Duration) *sender {

	return &sender{
		n:             n,
		timeout:       newSafeTimeout(),
		newData:       make(chan *PacketData),
		ackChan:       make(chan uint8, n),
		nackChan:      make(chan uint8, n),
		resendTimeout: resendTimeout,
		log:           logger,
		sendFn:        sendFn,
		sendQueue: newQueue(&queueCfg{
			s:       n + 1,
			timeout: resendTimeout,
			log:     logger,
			sendPkt: sendFn,
		}),
		errChan:           errChan,
		receivedACKSignal: make(chan struct{}),
		resendSignal:      make(chan struct{}, 1),
		quit:              make(chan struct{}),
	}
}

func (s *sender) stop() {
	close(s.quit)
	s.wg.Wait()

	if s.resendTicker != nil {
		s.resendTicker.Stop()
	}
	s.pingTickerMu.Lock()
	if s.pingTicker != nil {
		s.pingTicker.Stop()
	}
	s.pingTickerMu.Unlock()
}

func (s *sender) start() {
	pingTime := time.Duration(math.MaxInt64)
	if s.pingTime != 0 {
		pingTime = s.pingTime
	}

	s.pingTicker = NewIntervalAwareForceTicker(pingTime)
	s.pingTicker.Resume()

	pongTime := time.Duration(math.MaxInt64)
	if s.pongTime != 0 {
		pongTime = s.pongTime
	}

	s.pongTicker = NewIntervalAwareForceTicker(pongTime)
	s.resendTicker = time.NewTicker(s.resendTimeout)

	s.wg.Add(1)
	go s.handleAcksAndNacks()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		err := s.handleQueueContents()
		if err != nil {
			s.errChan <- err
		}
	}()
}

func (s *sender) handleQueueContents() error {
	for {
		// The queue is not full. If we receive a resend signal or if
		// the resend timeout passes then we resend the current contents
		// of the queue. Otherwise, wait for more data to arrive on
		// sendDataChan.
		var packet *PacketData
		select {
		case <-s.quit:
			return nil

		case <-s.resendSignal:
			if err := s.sendQueue.resend(); err != nil {
				return err
			}

			continue

		case <-s.resendTicker.C:
			if err := s.sendQueue.resend(); err != nil {
				return err
			}
			continue

		case <-s.pingTicker.Ticks():

			// Start the pong timer.
			s.pongTicker.Reset()
			s.pongTicker.Resume()

			s.log.Tracef("Sending a PING packet")

			packet = &PacketData{
				IsPing: true,
			}

		case <-s.pongTicker.Ticks():
			return errKeepaliveTimeout

		case packet = <-s.newData:
		}

		// New data has arrived that we need to add to the queue and
		// send.
		s.sendQueue.addPacket(packet)

		s.log.Tracef("Sending data %d", packet.Seq)

		if err := s.sendFn(packet); err != nil {
			return err
		}

		for {
			// If the queue size is still less than N, we can
			// continue to add more packets to the queue.
			if s.sendQueue.size() < s.n {
				break
			}

			s.log.Tracef("The queue is full.")

			// The queue is full. We wait for a ACKs to arrive or
			// resend the queue after a timeout.
			select {
			case <-s.quit:
				return nil

			case <-s.receivedACKSignal:
				break

			case <-s.resendSignal:
				if err := s.sendQueue.resend(); err != nil {
					return err
				}

			case <-s.resendTicker.C:
				if err := s.sendQueue.resend(); err != nil {
					return err
				}
			}
		}
	}
}

func (s *sender) handleAcksAndNacks() {
	defer s.wg.Done()

	var ackSeq, nackSeq uint8
	for {
		select {
		case ackSeq = <-s.ackChan:
			s.handleACK(ackSeq)

		case nackSeq = <-s.nackChan:
			s.handleNACK(nackSeq)

		case <-s.quit:
			return
		}
	}
}

func (s *sender) handleACK(seq uint8) {
	gotValidACK := s.sendQueue.processACK(seq)
	if gotValidACK {
		s.resendTicker.Reset(s.resendTimeout)

		// Send a signal to indicate that new
		// ACKs have been received.
		select {
		case s.receivedACKSignal <- struct{}{}:
		default:
		}
	}
}

func (s *sender) handleNACK(seq uint8) {
	// We received a NACK packet. This means that the receiver got a data
	// packet that they were not expecting. This likely means that a packet
	// that we sent was dropped, or maybe we sent a duplicate message. The
	// NACK message contains the sequence number that the receiver was
	// expecting.
	inQueue, bumped := s.sendQueue.processNACK(seq)

	// If the NACK sequence number is not in our queue
	// then we ignore it. We must have received the ACK
	// for the sequence number in the meantime.
	if !inQueue {
		s.log.Tracef("NACK seq %d is not in the queue. Ignoring", seq)

		return
	}

	// If the base was bumped, then the queue is now smaller
	// and so we can send a signal to indicate this.
	if bumped {
		select {
		case s.receivedACKSignal <- struct{}{}:
		default:
		}
	}

	s.log.Tracef("Sending a resend signal")

	// Send a signal to indicate that new sends should pause
	// and the current queue should be resent instead.
	select {
	case s.resendSignal <- struct{}{}:
	default:
	}
}

func (s *sender) Send(data []byte) error {
	select {
	case <-s.quit:
		return io.EOF
	default:
	}

	ticker := time.NewTimer(s.timeout.get())
	defer ticker.Stop()

	// sendData sends the given data message onto the dataToSend channel.
	sendData := func(packet *PacketData) error {
		select {
		case s.newData <- packet:
			return nil
		case <-ticker.C:
			return errSendTimeout
		case <-s.quit:
			return fmt.Errorf("cannot send, sender has exited")
		}
	}

	// If splitting is disabled, then we set the packet's FinalChunk to
	// true.
	if s.maxChunkSize == 0 {
		return sendData(&PacketData{
			Payload:    data,
			FinalChunk: true,
		})
	}

	// Splitting is enabled. Split into packets no larger than maxChunkSize.
	var (
		sentBytes = 0
		maxChunk  = s.maxChunkSize
	)
	for sentBytes < len(data) {
		var msg PacketData

		remainingBytes := len(data) - sentBytes
		if remainingBytes <= maxChunk {
			msg.Payload = data[sentBytes:]
			msg.FinalChunk = true

			sentBytes += remainingBytes
		} else {
			msg.Payload = data[sentBytes : sentBytes+maxChunk]

			sentBytes += maxChunk
		}

		if err := sendData(&msg); err != nil {
			return err
		}
	}

	return nil
}

func (s *sender) ACK(u uint8) {
	select {
	case <-s.quit:
		return
	case s.ackChan <- u:
	}
}

func (s *sender) NACK(u uint8) {
	select {
	case <-s.quit:
		return
	case s.nackChan <- u:
	}
}

func (s *sender) SetTimeout(duration time.Duration) {
	s.timeout.set(duration)
}

var _ Sender = (*sender)(nil)
