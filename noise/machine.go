package noise

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrMaxMessageLengthExceeded is returned a message to be written to
	// the cipher session exceeds the maximum allowed message payload.
	ErrMaxMessageLengthExceeded = errors.New("the generated payload exceeds " +
		"the max allowed message length of (2^16)-1")

	// ErrMessageNotFlushed signals that the connection cannot accept a new
	// message because the prior message has not been fully flushed.
	ErrMessageNotFlushed = errors.New("prior message not flushed")
)

type Machine struct {
	sendCipher cipherState
	recvCipher cipherState

	ephemeralGen func() (*btcec.PrivateKey, error)

	// nextCipherHeader is a static buffer that we'll use to read in the
	// next ciphertext header from the wire. The header is a 2 byte length
	// (of the next ciphertext), followed by a 16 byte MAC.
	nextCipherHeader [encHeaderSize]byte

	// nextHeaderSend holds a reference to the remaining header bytes to
	// write out for a pending message. This allows us to tolerate timeout
	// errors that cause partial writes.
	nextHeaderSend []byte

	// nextHeaderBody holds a reference to the remaining body bytes to write
	// out for a pending message. This allows us to tolerate timeout errors
	// that cause partial writes.
	nextBodySend []byte

	handshakeState
}

func NewMachine(initiator bool, localStatic keychain.SingleKeyECDH,
	remoteStatic *btcec.PublicKey, passphrase []byte,
	authData []byte, handshakeVersion byte) (*Machine, error) {

	// We always stretch the passphrase here in order to partially thwart
	// brute force attempts, and also ensure we obtain a high entropy
	// blidning point.
	password, err := stretchPassword(passphrase)
	if err != nil {
		return nil, err
	}

	handshake := newHandshakeState(
		handshakeVersion, initiator, lightningNodeConnectPrologue,
		localStatic, remoteStatic, password, authData,
	)

	m := &Machine{
		handshakeState: handshake,
	}

	// With the default options established, we'll now process all the
	// options passed in as parameters.
	//for _, option := range options {
	//	option(m)
	//}

	return m, nil
}

func (m *Machine) DoHandshake(rw io.ReadWriter) error {
	for i := 0; i < len(m.pattern.Pattern); i++ {
		mp := m.pattern.Pattern[i]

		if mp.initiator == m.initiator {
			if err := m.writeMsgPattern(mp, rw); err != nil {
				return err
			}
			continue
		}

		if err := m.readMsgPattern(rw, mp); err != nil {
			return err
		}
	}

	m.split()

	return nil
}

// split is the final wrap-up act to be executed at the end of a successful
// three act handshake. This function creates two internal cipherState
// instances: one which is used to encrypt messages from the initiator to the
// responder, and another which is used to encrypt message for the opposite
// direction.
func (m *Machine) split() {
	var (
		empty   []byte
		sendKey [32]byte
		recvKey [32]byte
	)

	h := hkdf.New(sha256.New, empty, m.ck[:], empty)

	// If we're the initiator the first 32 bytes are used to encrypt our
	// messages and the second 32-bytes to decrypt their messages. For the
	// responder the opposite is true.
	if m.initiator {
		_, _ = h.Read(sendKey[:])
		m.sendCipher = cipherState{}
		m.sendCipher.InitializeKeyWithSalt(m.ck, sendKey)

		_, _ = h.Read(recvKey[:])
		m.recvCipher = cipherState{}
		m.recvCipher.InitializeKeyWithSalt(m.ck, recvKey)
	} else {
		_, _ = h.Read(recvKey[:])
		m.recvCipher = cipherState{}
		m.recvCipher.InitializeKeyWithSalt(m.ck, recvKey)

		_, _ = h.Read(sendKey[:])
		m.sendCipher = cipherState{}
		m.sendCipher.InitializeKeyWithSalt(m.ck, sendKey)
	}
}

// WriteMessage encrypts and buffers the next message p. The ciphertext of the
// message is prepended with an encrypt+auth'd length which must be used as the
// AD to the AEAD construction when being decrypted by the other side.
//
// NOTE: This DOES NOT write the message to the wire, it should be followed by a
// call to Flush to ensure the message is written.
func (b *Machine) WriteMessage(p []byte) error {
	// The total length of each message payload including the MAC size
	// payload exceed the largest number encodable within a 16-bit unsigned
	// integer.
	if len(p) > math.MaxUint16 {
		return ErrMaxMessageLengthExceeded
	}

	// If a prior message was written but it hasn't been fully flushed,
	// return an error as we only support buffering of one message at a
	// time.
	if len(b.nextHeaderSend) > 0 || len(b.nextBodySend) > 0 {
		return ErrMessageNotFlushed
	}

	// The full length of the packet is only the packet length, and does
	// NOT include the MAC.
	fullLength := uint16(len(p))

	var pktLen [2]byte
	binary.BigEndian.PutUint16(pktLen[:], fullLength)

	// First, generate the encrypted+MAC'd length prefix for the packet.
	b.nextHeaderSend = b.sendCipher.Encrypt(nil, pktLen[:])

	// Finally, generate the encrypted packet itself.
	b.nextBodySend = b.sendCipher.Encrypt(nil, p)

	return nil
}

// Flush attempts to write a message buffered using WriteMessage to the provided
// io.Writer. If no buffered message exists, this will result in a NOP.
// Otherwise, it will continue to write the remaining bytes, picking up where
// the byte stream left off in the event of a partial write. The number of bytes
// returned reflects the number of plaintext bytes in the payload, and does not
// account for the overhead of the header or MACs.
//
// NOTE: It is safe to call this method again iff a timeout error is returned.
func (b *Machine) Flush(w io.Writer) (int, error) {
	// First, write out the pending header bytes, if any exist. Any header
	// bytes written will not count towards the total amount flushed.
	if len(b.nextHeaderSend) > 0 {
		// Write any remaining header bytes and shift the slice to point
		// to the next segment of unwritten bytes. If an error is
		// encountered, we can continue to write the header from where
		// we left off on a subsequent call to Flush.
		n, err := w.Write(b.nextHeaderSend)
		b.nextHeaderSend = b.nextHeaderSend[n:]
		if err != nil {
			return 0, err
		}
	}

	// Next, write the pending body bytes, if any exist. Only the number of
	// bytes written that correspond to the ciphertext will be included in
	// the total bytes written, bytes written as part of the MAC will not be
	// counted.
	var nn int
	if len(b.nextBodySend) > 0 {
		// Write out all bytes excluding the mac and shift the body
		// slice depending on the number of actual bytes written.
		n, err := w.Write(b.nextBodySend)
		b.nextBodySend = b.nextBodySend[n:]

		// If we partially or fully wrote any of the body's MAC, we'll
		// subtract that contribution from the total amount flushed to
		// preserve the abstraction of returning the number of plaintext
		// bytes written by the connection.
		//
		// There are three possible scenarios we must handle to ensure
		// the returned value is correct. In the first case, the write
		// straddles both payload and MAC bytes, and we must subtract
		// the number of MAC bytes written from n. In the second, only
		// payload bytes are written, thus we can return n unmodified.
		// The final scenario pertains to the case where only MAC bytes
		// are written, none of which count towards the total.
		//
		//                 |-----------Payload------------|----MAC----|
		// Straddle:       S---------------------------------E--------0
		// Payload-only:   S------------------------E-----------------0
		// MAC-only:                                        S-------E-0
		start, end := n+len(b.nextBodySend), len(b.nextBodySend)
		switch {

		// Straddles payload and MAC bytes, subtract number of MAC bytes
		// written from the actual number written.
		case start > macSize && end <= macSize:
			nn = n - (macSize - end)

		// Only payload bytes are written, return n directly.
		case start > macSize && end > macSize:
			nn = n

		// Only MAC bytes are written, return 0 bytes written.
		default:
		}

		if err != nil {
			return nn, err
		}
	}

	return nn, nil
}

// ReadMessage attempts to read the next message from the passed io.Reader. In
// the case of an authentication error, a non-nil error is returned.
func (b *Machine) ReadMessage(r io.Reader) ([]byte, error) {
	pktLen, err := b.ReadHeader(r)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): need to be able to handle messages over multiple
	// protocol messages?

	buf := make([]byte, pktLen)
	return b.ReadBody(r, buf)
}

// ReadHeader attempts to read the next message header from the passed
// io.Reader. The header contains the length of the next body including
// additional overhead of the MAC. In the case of an authentication error, a
// non-nil error is returned.
//
// NOTE: This method SHOULD NOT be used in the case that the io.Reader may be
// adversarial and induce long delays. If the caller needs to set read deadlines
// appropriately, it is preferred that they use the split ReadHeader and
// ReadBody methods so that the deadlines can be set appropriately on each.
func (b *Machine) ReadHeader(r io.Reader) (uint32, error) {
	_, err := io.ReadFull(r, b.nextCipherHeader[:])
	if err != nil {
		return 0, err
	}

	// Attempt to decrypt+auth the packet length present in the stream.
	pktLenBytes, err := b.recvCipher.Decrypt(nil, b.nextCipherHeader[:])
	if err != nil {
		return 0, err
	}

	// Compute the packet length that we will need to read off the wire.
	pktLen := uint32(binary.BigEndian.Uint16(pktLenBytes)) + macSize

	return pktLen, nil
}

// ReadBody attempts to ready the next message body from the passed io.Reader.
// The provided buffer MUST be the length indicated by the packet length
// returned by the preceding call to ReadHeader. In the case of an
// authentication eerror, a non-nil error is returned.
func (b *Machine) ReadBody(r io.Reader, buf []byte) ([]byte, error) {
	// Next, using the length read from the packet header, read the
	// encrypted packet itself into the buffer allocated by the read
	// pool.
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	// Finally, decrypt the message held in the buffer, and return a
	// new byte slice containing the plaintext.
	// TODO(roasbeef): modify to let pass in slice
	return b.recvCipher.Decrypt(nil, buf)
}
