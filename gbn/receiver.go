package gbn

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

type Receiver interface {
	Receive() ([]byte, error)
	GotData(data *PacketData)
	SetTimeout(duration time.Duration)
}

// receiver is only interested in receiving DATA packets, and sending ACKs and
// NACKs for them.
type receiver struct {
	// s is the maximum sequence number used to label packets. Packets
	// are labelled with incrementing sequence numbers modulo s.
	s uint8

	sendPkt func(Message) error

	timeout *safeTimeout

	expectedSeq  uint8
	lastNackSeq  uint8
	lastNackTime time.Time

	resendTimeout time.Duration

	newDataChan       chan *PacketData
	processedDataChan chan *PacketData

	log btclog.Logger

	errChan chan error
	quit    chan struct{}
	wg      sync.WaitGroup
}

var _ Receiver = (*receiver)(nil)

func newReceiver(s uint8, sendFn func(Message) error,
	errChan chan error, resendTimeout time.Duration,
	logger btclog.Logger) *receiver {

	return &receiver{
		s:                 s,
		sendPkt:           sendFn,
		timeout:           newSafeTimeout(),
		resendTimeout:     resendTimeout,
		newDataChan:       make(chan *PacketData, s),
		processedDataChan: make(chan *PacketData, s),
		log:               logger,
		errChan:           errChan,
		quit:              make(chan struct{}),
	}
}

func (r *receiver) start() {
	r.wg.Add(1)
	go r.receiveForever()
}

func (r *receiver) receiveForever() {
	defer r.wg.Done()

	var err error
	for {
		select {
		case pkt := <-r.newDataChan:
			if pkt.Seq != r.expectedSeq {
				err = r.handleUnexpectedPkt(pkt)
				if err != nil {
					r.errChan <- err

					return
				}

				continue
			}

			err = r.handleExpectedPkt(pkt)
			if err != nil {
				r.errChan <- err

				return
			}

		case <-r.quit:
			return
		}
	}
}

func (r *receiver) handleExpectedPkt(pkt *PacketData) error {
	// We received a data packet with the sequence number we were expecting.
	// So we respond with an ACK message with that sequence number and we
	// bump the sequence number that we expect of the next data packet.
	r.log.Tracef("Got expected data %d", pkt.Seq)

	ack := &PacketACK{
		Seq: pkt.Seq,
	}

	if err := r.sendPkt(ack); err != nil {
		return err
	}

	r.expectedSeq = (r.expectedSeq + 1) % r.s

	// If the packet was a ping, then there is no data to return to the
	// above layer.
	if pkt.IsPing {
		return nil
	}

	// Pass the returned packet to the layer above
	// GBN.
	select {
	case r.processedDataChan <- pkt:
	case <-r.quit:
		return nil
	}

	return nil
}

func (r *receiver) handleUnexpectedPkt(pkt *PacketData) error {
	// We received a data packet with a sequence number that we were not
	// expecting. This could be a packet that we have already received and
	// that is being resent because the ACK for it was not received in time
	// or it could be that we missed a previous packet. In either case, we
	// send a NACK with the sequence number that we were expecting.
	r.log.Tracef("Got unexpected data %d", pkt.Seq)

	// If we recently sent a NACK for the same sequence number then back
	// off.
	if r.lastNackSeq == r.expectedSeq && time.Since(r.lastNackTime) <
		r.resendTimeout {

		return nil
	}

	r.log.Tracef("Sending NACK %d", r.expectedSeq)

	// Send a NACK with the expected sequence
	// number.
	nack := &PacketNACK{
		Seq: r.expectedSeq,
	}

	if err := r.sendPkt(nack); err != nil {
		return err
	}

	r.lastNackTime = time.Now()
	r.lastNackSeq = nack.Seq

	return nil
}

func (r *receiver) Receive() ([]byte, error) {
	select {
	case <-r.quit:
		return nil, io.EOF
	default:
	}

	var (
		b   []byte
		msg *PacketData
	)

	ticker := time.NewTimer(r.timeout.get())
	defer ticker.Stop()

	for {
		select {
		case <-r.quit:
			return nil, fmt.Errorf("cannot receive, receiver " +
				"exited")
		case <-ticker.C:
			return nil, errRecvTimeout
		case msg = <-r.processedDataChan:
		}

		b = append(b, msg.Payload...)

		if msg.FinalChunk {
			break
		}
	}

	return b, nil
}

func (r *receiver) GotData(data *PacketData) {
	select {
	case <-r.quit:
	case r.newDataChan <- data:
	}
}

func (r *receiver) SetTimeout(duration time.Duration) {
	r.timeout.set(duration)
}

func (r *receiver) stop() {
	close(r.quit)
	r.wg.Wait()
}
