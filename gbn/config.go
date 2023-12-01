package gbn

import "time"

// config holds the configuration values for an instance of GoBackNConn.
type config struct {
	// n is the window size. The sender can send a maximum of n packets
	// before requiring an ack from the receiver for the first packet in
	// the window. The value of n is chosen by the client during the
	// GoBN handshake.
	n uint8

	// maxChunkSize is the maximum payload size in bytes allowed per
	// message. If the payload to be sent is larger than maxChunkSize then
	// the payload will be split between multiple packets.
	// If maxChunkSize is zero then it is disabled and data won't be split
	// between packets.
	maxChunkSize int

	// resendTimeout is the duration that will be waited before resending
	// the packets in the current queue.
	resendTimeout time.Duration

	// recvFromStream is the function that will be used to acquire the next
	// available packet.
	recvFromStream recvBytesFunc

	// sendToStream is the function that will be used to send over our next
	// packet.
	sendToStream sendBytesFunc

	// handshakeTimeout is the time after which the server or client
	// will abort and restart the handshake if the expected response is
	// not received from the peer.
	handshakeTimeout time.Duration

	pingTime time.Duration
	pongTime time.Duration
}

// newConfig constructs a new config struct.
func newConfig(sendFunc sendBytesFunc, recvFunc recvBytesFunc,
	n uint8) *config {

	return &config{
		n:                n,
		recvFromStream:   recvFunc,
		sendToStream:     sendFunc,
		resendTimeout:    defaultResendTimeout,
		handshakeTimeout: defaultHandshakeTimeout,
	}
}
