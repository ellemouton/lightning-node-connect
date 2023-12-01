package gbn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btclog"
	"github.com/lightningnetwork/lnd/build"
)

var (
	errTransportClosing = errors.New("gbn transport is closing")
	errKeepaliveTimeout = errors.New("no pong received")
	errSendTimeout      = errors.New("send timeout")
	errRecvTimeout      = errors.New("receive timeout")
)

const (
	DefaultN                = 20
	defaultHandshakeTimeout = 100 * time.Millisecond
	defaultResendTimeout    = 100 * time.Millisecond
	finSendTimeout          = 1000 * time.Millisecond
)

type sendBytesFunc func(ctx context.Context, b []byte) error
type recvBytesFunc func(ctx context.Context) ([]byte, error)

type GBN interface {
	Send([]byte) error
	Recv() ([]byte, error)
	SetRecvTimeout(timeout time.Duration)
	SetSendTimeout(timeout time.Duration)
	Close() error
}

type gbn struct {
	cfg *config

	// s is the maximum sequence number used to label packets. Packets
	// are labelled with incrementing sequence numbers modulo s.
	// s must be strictly larger than the window size, n. This
	// is so that the receiver can tell if the sender is resending the
	// previous window (maybe the sender did not receive the acks) or if
	// they are sending the next window. If s <= n then there would be
	// no way to tell.
	s uint8

	ctx    context.Context //nolint:containedctx
	cancel func()

	sender      *sender
	senderErr   chan error
	receiver    *receiver
	receiverErr chan error

	// remoteClosed is closed if the remote party initiated the FIN sequence.
	remoteClosed chan struct{}

	log btclog.Logger

	quit      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	errChan   chan error
}

func newGBN(ctx context.Context, cfg *config, loggerPrefix string) *gbn {
	ctxc, cancel := context.WithCancel(ctx)

	// Construct a new prefixed logger.
	prefix := fmt.Sprintf("(%s)", loggerPrefix)
	plog := build.NewPrefixLog(prefix, log)

	senderErr := make(chan error, 1)
	receiverErr := make(chan error, 1)

	g := &gbn{
		cfg:          cfg,
		ctx:          ctxc,
		cancel:       cancel,
		log:          plog,
		senderErr:    senderErr,
		receiverErr:  receiverErr,
		remoteClosed: make(chan struct{}),
		errChan:      make(chan error, 1),
		quit:         make(chan struct{}),
	}

	g.sender = newSender(
		cfg.n, g.sendPacket, senderErr, plog, cfg.resendTimeout,
	)

	g.receiver = newReceiver(
		cfg.n+1, g.sendPacket, receiverErr, cfg.resendTimeout, plog,
	)

	return g
}

func (g *gbn) setN(n uint8) {
	g.cfg.n = n
	g.s = n + 1
	g.sender = newSender(
		g.cfg.n, g.sendPacket, g.senderErr, g.log, g.cfg.resendTimeout,
	)
	g.receiver = newReceiver(
		g.cfg.n+1, g.sendPacket, g.receiverErr, g.cfg.resendTimeout,
		g.log,
	)
}

func (g *gbn) Send(data []byte) error {
	return g.sender.Send(data)
}

func (g *gbn) Recv() ([]byte, error) {
	return g.receiver.Receive()
}

// start kicks off the various goroutines needed by GoBackNConn.
// start should only be called once the handshake has been completed.
func (g *gbn) start() {
	g.log.Debugf("Starting")

	g.wg.Add(1)
	go g.packetDistributor()

	g.sender.start()
	g.receiver.start()

	go func() {
		var (
			err         error
			errProducer string
		)

		select {
		case <-g.senderErr:
			errProducer = "sender"
		case <-g.receiverErr:
			errProducer = "receiver"
		case <-g.errChan:
			errProducer = "gbn"
		case <-g.quit:
			return
		}

		g.log.Errorf("Error from %s: %v", errProducer, err)

		if err := g.Close(); err != nil {
			g.log.Errorf("Error closing gbn: %v", err)
		}
	}()
}

func (g *gbn) receivePacket() (Message, error) {
	b, err := g.cfg.recvFromStream(g.ctx)
	if err != nil {
		return nil, fmt.Errorf("error receiving from stream: %w", err)
	}

	m, err := Deserialize(b)
	if err != nil {
		return nil, err
	}

	g.sender.AnyReceive()

	return m, nil
}

func (g *gbn) sendPacket(msg Message) error {
	b, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("serialize error: %s", err)
	}

	err = g.cfg.sendToStream(g.ctx, b)
	if err != nil {
		return fmt.Errorf("error calling sendToStream: %s", err)
	}

	return nil
}

func (g *gbn) sendPacketWithCtx(ctx context.Context, msg Message) error {
	b, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("serialize error: %s", err)
	}

	err = g.cfg.sendToStream(ctx, b)
	if err != nil {
		return fmt.Errorf("error calling sendToStream: %s", err)
	}

	return nil
}

func (g *gbn) packetDistributor() {
	defer g.wg.Done()

	for {
		select {
		case <-g.quit:
			return
		default:
		}

		msg, err := g.receivePacket()
		if err != nil {
			g.errChan <- fmt.Errorf("deserialize error: %s", err)

			return
		}

		switch m := msg.(type) {
		case *PacketData:
			// Send DATA packets to the receiver.
			g.receiver.GotData(m)

		case *PacketACK:
			// ACKs go to the sender.
			g.sender.ACK(m.Seq)

		case *PacketNACK:
			// NACKs go to the sender.
			g.sender.NACK(m.Seq)

		case *PacketFIN:
			// A FIN packet indicates that the peer would like to
			// close the connection.
			g.log.Tracef("Received a FIN packet")

			close(g.remoteClosed)
			g.errChan <- errTransportClosing

		default:
			g.errChan <- fmt.Errorf("received unhandled message: "+
				"%T", msg)

			return
		}
	}
}

func (g *gbn) Close() error {
	g.closeOnce.Do(func() {
		g.log.Debugf("Closing GBN")

		// Canceling the context will ensure that we are not hanging on
		// the receive or send functions passed to the server on
		// initialisation.
		g.cancel()

		// We close the quit channel to stop the usual operations of the
		// server.
		close(g.quit)

		// Try send a FIN message to the peer if they have not already
		// done so.
		select {
		case <-g.remoteClosed:
		default:
			g.log.Tracef("Try sending FIN")

			ctxc, cancel := context.WithTimeout(
				g.ctx, finSendTimeout,
			)
			defer cancel()

			err := g.sendPacketWithCtx(ctxc, &PacketFIN{})
			if err != nil {
				g.log.Errorf("Error sending FIN: %v", err)
			}
		}

		g.receiver.stop()
		g.sender.stop()

		g.wg.Wait()

		g.log.Debugf("GBN is closed")
	})

	return nil
}

func (g *gbn) SetRecvTimeout(t time.Duration) {
	g.receiver.SetTimeout(t)
}

func (g *gbn) SetSendTimeout(t time.Duration) {
	g.sender.SetTimeout(t)
}

var _ GBN = (*gbn)(nil)
