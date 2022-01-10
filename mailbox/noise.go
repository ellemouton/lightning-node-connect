package mailbox

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// protocolName is the precise instantiation of the Noise protocol
	// handshake at the center of our modified Brontide handshake. This
	// value will be used as part of the prologue. If the initiator and
	// responder aren't using the exact same string for this value, along
	// with prologue of the Bitcoin network, then the initial handshake
	// will fail.
	protocolName = "Noise_XXeke+SPAKE2_secp256k1_ChaChaPoly_SHA256"

	// macSize is the length in bytes of the tags generated by poly1305.
	macSize = 16

	// lengthHeaderSize is the number of bytes used to prefix encode the
	// length of a message payload.
	lengthHeaderSize = 2

	// encHeaderSize is the number of bytes required to hold an encrypted
	// header and it's MAC.
	encHeaderSize = lengthHeaderSize + macSize

	// keyRotationInterval is the number of messages sent on a single
	// cipher stream before the keys are rotated forwards.
	keyRotationInterval = 1000

	// handshakeReadTimeout is a read timeout that will be enforced when
	// waiting for data payloads during the various acts of Brontide. If
	// the remote party fails to deliver the proper payload within this
	// time frame, then we'll fail the connection.
	handshakeReadTimeout = time.Second * 5
)

var (
	// ErrMaxMessageLengthExceeded is returned a message to be written to
	// the cipher session exceeds the maximum allowed message payload.
	ErrMaxMessageLengthExceeded = errors.New("the generated payload exceeds " +
		"the max allowed message length of (2^16)-1")

	// ErrMessageNotFlushed signals that the connection cannot accept a new
	// message because the prior message has not been fully flushed.
	ErrMessageNotFlushed = errors.New("prior message not flushed")

	// lightningNodeConnectPrologue is the noise prologue that is used to
	// initialize the brontide noise handshake.
	lightningNodeConnectPrologue = []byte("lightning-node-connect")

	// ephemeralGen is the default ephemeral key generator, used to derive a
	// unique ephemeral key for each brontide handshake.
	ephemeralGen = func() (*btcec.PrivateKey, error) {
		return btcec.NewPrivateKey(btcec.S256())
	}

	// N is the generator point we'll use for our PAKE protocol. It was
	// generated via a try-and-increment approach using the phrase
	// "Lightning Node Connect" with SHA2-256.
	nBytes, _ = hex.DecodeString(
		"0254a58cd0f31c008fd0bc9b2dd5ba586144933829f6da33ac4130b555fb5ea32c",
	)
	N, _ = btcec.ParsePubKey(nBytes, btcec.S256())
)

// ecdh performs an ECDH operation between pub and priv. The returned value is
// the sha256 of the compressed shared point.
func ecdh(pub *btcec.PublicKey, priv keychain.SingleKeyECDH) ([]byte, error) {
	hash, err := priv.ECDH(pub)
	return hash[:], err
}

// cipherState encapsulates the state for the AEAD which will be used to
// encrypt+authenticate any payloads sent during the handshake, and messages
// sent once the handshake has completed.
type cipherState struct {
	// nonce is the nonce passed into the chacha20-poly1305 instance for
	// encryption+decryption. The nonce is incremented after each successful
	// encryption/decryption.
	nonce uint64

	// secretKey is the shared symmetric key which will be used to
	// instantiate the cipher.
	secretKey [32]byte

	// salt is an additional secret which is used during key rotation to
	// generate new keys.
	salt [32]byte

	// cipher is an instance of the ChaCha20-Poly1305 AEAD construction
	// created using the secretKey above.
	cipher cipher.AEAD
}

// Encrypt returns a ciphertext which is the encryption of the plainText
// observing the passed associatedData within the AEAD construction.
func (c *cipherState) Encrypt(associatedData, cipherText, plainText []byte) []byte {
	defer func() {
		c.nonce++

		if c.nonce == keyRotationInterval {
			c.rotateKey()
		}
	}()

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.nonce)

	// TODO(roasbeef): should just return plaintext?

	return c.cipher.Seal(cipherText, nonce[:], plainText, associatedData)
}

// Decrypt attempts to decrypt the passed ciphertext observing the specified
// associatedData within the AEAD construction. In the case that the final MAC
// check fails, then a non-nil error will be returned.
func (c *cipherState) Decrypt(associatedData, plainText, cipherText []byte) ([]byte, error) {
	defer func() {
		c.nonce++

		if c.nonce == keyRotationInterval {
			c.rotateKey()
		}
	}()

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.nonce)

	return c.cipher.Open(plainText, nonce[:], cipherText, associatedData)
}

// InitializeKey initializes the secret key and AEAD cipher scheme based off of
// the passed key.
func (c *cipherState) InitializeKey(key [32]byte) {
	c.secretKey = key
	c.nonce = 0

	// Safe to ignore the error here as our key is properly sized
	// (32-bytes).
	c.cipher, _ = chacha20poly1305.New(c.secretKey[:])
}

// InitializeKeyWithSalt is identical to InitializeKey however it also sets the
// cipherState's salt field which is used for key rotation.
func (c *cipherState) InitializeKeyWithSalt(salt, key [32]byte) {
	c.salt = salt
	c.InitializeKey(key)
}

// rotateKey rotates the current encryption/decryption key for this cipherState
// instance. Key rotation is performed by ratcheting the current key forward
// using an HKDF invocation with the cipherState's salt as the salt, and the
// current key as the input.
func (c *cipherState) rotateKey() {
	var (
		info    []byte
		nextKey [32]byte
	)

	oldKey := c.secretKey
	h := hkdf.New(sha256.New, oldKey[:], c.salt[:], info)

	// hkdf(ck, k, zero)
	// |
	// | \
	// |  \
	// ck  k'
	_, _ = h.Read(c.salt[:])
	_, _ = h.Read(nextKey[:])

	c.InitializeKey(nextKey)
}

// symmetricState encapsulates a cipherState object and houses the ephemeral
// handshake digest state. This struct is used during the handshake to derive
// new shared secrets based off of the result of ECDH operations. Ultimately,
// the final key yielded by this struct is the result of an incremental
// Triple-DH operation.
type symmetricState struct {
	cipherState

	// chainingKey is used as the salt to the HKDF function to derive a new
	// chaining key as well as a new tempKey which is used for
	// encryption/decryption.
	chainingKey [32]byte

	// tempKey is the latter 32 bytes resulted from the latest HKDF
	// iteration. This key is used to encrypt/decrypt any handshake
	// messages or payloads sent until the next DH operation is executed.
	tempKey [32]byte

	// handshakeDigest is the cumulative hash digest of all handshake
	// messages sent from start to finish. This value is never transmitted
	// to the other side, but will be used as the AD when
	// encrypting/decrypting messages using our AEAD construction.
	handshakeDigest [32]byte
}

// mixKey is implements a basic HKDF-based key ratchet. This method is called
// with the result of each DH output generated during the handshake process.
// The first 32 bytes extract from the HKDF reader is the next chaining key,
// then latter 32 bytes become the temp secret key using within any future AEAD
// operations until another DH operation is performed.
func (s *symmetricState) mixKey(input []byte) {
	var info []byte

	secret := input
	salt := s.chainingKey
	h := hkdf.New(sha256.New, secret, salt[:], info)

	// hkdf(ck, input, zero)
	// |
	// | \
	// |  \
	// ck  k
	_, _ = h.Read(s.chainingKey[:])
	_, _ = h.Read(s.tempKey[:])

	// cipher.k = temp_key
	s.InitializeKey(s.tempKey)
}

// mixHash hashes the passed input data into the cumulative handshake digest.
// The running result of this value (h) is used as the associated data in all
// decryption/encryption operations.
func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	_, _ = h.Write(s.handshakeDigest[:])
	_, _ = h.Write(data)

	copy(s.handshakeDigest[:], h.Sum(nil))
}

// EncryptAndHash returns the authenticated encryption of the passed plaintext.
// When encrypting the handshake digest (h) is used as the associated data to
// the AEAD cipher.
func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	ciphertext := s.Encrypt(s.handshakeDigest[:], nil, plaintext)

	s.mixHash(ciphertext)

	return ciphertext
}

// DecryptAndHash returns the authenticated decryption of the passed
// ciphertext.  When encrypting the handshake digest (h) is used as the
// associated data to the AEAD cipher.
func (s *symmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.Decrypt(s.handshakeDigest[:], nil, ciphertext)
	if err != nil {
		return nil, err
	}

	s.mixHash(ciphertext)

	return plaintext, nil
}

// InitializeSymmetric initializes the symmetric state by setting the handshake
// digest (h) and the chaining key (ck) to protocol name.
func (s *symmetricState) InitializeSymmetric(protocolName []byte) {
	var empty [32]byte

	s.handshakeDigest = sha256.Sum256(protocolName)
	s.chainingKey = s.handshakeDigest
	s.InitializeKey(empty)
}

// handshakeState encapsulates the symmetricState and keeps track of all the
// public keys (static and ephemeral) for both sides during the handshake
// transcript. If the handshake completes successfully, then two instances of a
// cipherState are emitted: one to encrypt messages from initiator to
// responder, and the other for the opposite direction.
type handshakeState struct {
	symmetricState

	initiator bool

	localStatic    keychain.SingleKeyECDH
	localEphemeral keychain.SingleKeyECDH // nolint (false positive)

	remoteStatic    *btcec.PublicKey // nolint
	remoteEphemeral *btcec.PublicKey // nolint
}

// newHandshakeState returns a new instance of the handshake state initialized
// with the prologue and protocol name. If this is the responder's handshake
// state, then the remotePub can be nil.
func newHandshakeState(initiator bool, prologue []byte,
	localPub keychain.SingleKeyECDH) handshakeState {

	h := handshakeState{
		initiator:   initiator,
		localStatic: localPub,
	}

	// Set the current chaining key and handshake digest to the hash of the
	// protocol name, and additionally mix in the prologue. If either sides
	// disagree about the prologue or protocol name, then the handshake
	// will fail.
	h.InitializeSymmetric([]byte(protocolName))
	h.mixHash(prologue)

	// TODO(roasbeef): if did mixHash here w/ the password, then the same
	// as using it as a PSK?

	return h
}

// EphemeralGenerator is a functional option that allows callers to substitute
// a custom function for use when generating ephemeral keys for ActOne or
// ActTwo.  The function closure return by this function can be passed into
// NewBrontideMachine as a function option parameter.
func EphemeralGenerator(gen func() (*btcec.PrivateKey, error)) func(*Machine) {
	return func(m *Machine) {
		m.ephemeralGen = gen
	}
}

// AuthDataPayload is a functional option that allows the non-initiator to
// specify a piece of data that should be sent to the initiator during the
// final phase of the handshake. This information is typically something like a
// macaroon.
func AuthDataPayload(authData []byte) func(*Machine) {
	return func(m *Machine) {
		m.authData = authData
	}
}

// Machine is a state-machine which implements Brontide: an Authenticated-key
// Exchange in Three Acts. Brontide is derived from the Noise framework,
// specifically implementing the Noise_XX handshake with an eke modified, where
// the public-key masking operation used is SPAKE2. Once the initial 3-act
// handshake has completed all messages are encrypted with a chacha20 AEAD
// cipher. On the wire, all messages are prefixed with an
// authenticated+encrypted length field. Additionally, the encrypted+auth'd
// length prefix is used as the AD when encrypting+decryption messages. This
// construction provides confidentiality of packet length, avoids introducing a
// padding-oracle, and binds the encrypted packet length to the packet itself.
//
// The acts proceeds the following order (initiator on the left):
//  GenActOne()   ->
//                    RecvActOne()
//                <-  GenActTwo()
//  RecvActTwo()
//  GenActThree() ->
//                    RecvActThree()
//
// This exchange corresponds to the following Noise handshake:
//   -> me
//   <- e, ee, s, es
//   -> s, se
//
// In this context, me is the masked ephemeral point that's masked using an
// operation derived from the traditional SPAKE2 protocol: e + h(pw)*M, where M
// is a generator of the cyclic group, h is a key derivation function, and pw is
// the password known to both sides.
//
// Note that there's also another operating mode based on Noise_IK which can be
// used after the initial pairing is complete and both sides have exchange
// long-term public keys.
type Machine struct {
	sendCipher cipherState
	recvCipher cipherState

	ephemeralGen func() (*btcec.PrivateKey, error)

	handshakeState

	// minHandshakeVersion is the minimum handshake version that the Machine
	// supports.
	minHandshakeVersion byte

	// maxHandshakeVersion is the maximum handshake version that the Machine
	// supports.
	maxHandshakeVersion byte

	// handshakeVersion is handshake version that the client and server have
	// agreed on.
	handshakeVersion byte

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

	// password if non-nil, then the Noise_XXeke handshake will be used.
	password []byte

	// authData is a special piece of authentication data that will be sent
	// from the responder to the initiator at the end of the handshake.
	// Typically this is a macaroon or some other piece of information used
	// to authenticate information.
	authData []byte
}

// TODO(roasbeef): eventually refactor into proper generic version that takes
// in the handshake messages?

// NewBrontideMachine creates a new instance of the brontide state-machine. If
// the responder (listener) is creating the object, then the remotePub should
// be nil. The handshake state within brontide is initialized using the ascii
// string "lightning" as the prologue. The last parameter is a set of variadic
// arguments for adding additional options to the brontide Machine
// initialization.
func NewBrontideMachine(initiator bool, localPub keychain.SingleKeyECDH,
	passphrase []byte, minVersion, maxVersion byte,
	options ...func(*Machine)) (*Machine, error) {

	handshake := newHandshakeState(
		initiator, lightningNodeConnectPrologue, localPub,
	)

	// We always stretch the passphrase here in order to partially thwart
	// brute force attempts, and also ensure we obtain a high entropy
	// blidning point.
	password, err := stretchPassword(passphrase)
	if err != nil {
		return nil, err
	}

	m := &Machine{
		handshakeState:      handshake,
		ephemeralGen:        ephemeralGen,
		password:            password,
		minHandshakeVersion: minVersion,
		maxHandshakeVersion: maxVersion,
		handshakeVersion:    maxVersion,
	}

	// With the default options established, we'll now process all the
	// options passed in as parameters.
	for _, option := range options {
		option(m)
	}

	return m, nil
}

// ekeMask masks the passed ephemeral key with the stored pass phrase, using
// SPAKE2 as the public masking operation: me = e + N*pw
func ekeMask(e *btcec.PublicKey, password []byte) *btcec.PublicKey {
	// me = e + N*pw
	passPointX, passPointY := btcec.S256().ScalarMult(N.X, N.Y, password)
	maskedEx, maskedEy := btcec.S256().Add(
		e.X, e.Y,
		passPointX, passPointY,
	)

	return &btcec.PublicKey{
		X:     maskedEx,
		Y:     maskedEy,
		Curve: btcec.S256(),
	}
}

// ekeUnmask does the inverse operation of ekeMask: e = me - N*pw
func ekeUnmask(me *btcec.PublicKey, password []byte) *btcec.PublicKey {
	// First, we'll need to re-generate the password point: N*pw
	passPointX, passPointY := btcec.S256().ScalarMult(N.X, N.Y, password)

	// With that generated, negate the y coordinate, then add that to the
	// masked point, which gives us the proper ephemeral key.
	passPointNegY := new(big.Int).Neg(passPointY)
	passPointNegY = passPointY.Mod(passPointNegY, btcec.S256().P)

	// e = me - N*pw
	eX, eY := btcec.S256().Add(
		me.X, me.Y,
		passPointX, passPointNegY,
	)

	return &btcec.PublicKey{
		X:     eX,
		Y:     eY,
		Curve: btcec.S256(),
	}
}

const (
	// HandshakeVersion0 is the handshake version in which the authData is
	// sent in act 2.
	HandshakeVersion0 = byte(0)

	// MinHandshakeVersion is the minimum handshake version that is
	// currently supported.
	MinHandshakeVersion = HandshakeVersion0

	// HandshakeVersion1 is the handshake version where the authData is
	// sent in act 4.
	HandshakeVersion1 = byte(1)

	// MaxHandshakeVersion is the maximum handshake that we currently
	// support. Any messages that carry a version not between
	// MinHandshakeVersion and MaxHandshakeVersion will cause the handshake
	// to abort immediately.
	MaxHandshakeVersion = HandshakeVersion1

	// ActOneSize is the size of the packet sent from initiator to
	// responder in ActOne. The packet consists of a handshake version, an
	// ephemeral key in compressed format, and a 16-byte poly1305 tag.
	//
	// 1 + 33 + 16
	ActOneSize = 50

	// ActTwoPayloadSize is the size of the fixed sized payload that can be
	// sent from the responder to the initiator in act two.
	ActTwoPayloadSize = 500

	// ActTwoSize is the size the packet sent from responder to initiator
	// in ActTwo. The packet consists of a handshake version, an ephemeral
	// key in compressed format, the static key of the responder (encrypted
	// with a 16 byte MAC), a fixed 500 bytes reserved for the auth
	// payload, and a 16-byte poly1305 tag.
	//
	// 1 + 33 + (33 + 16) + 500 + 16
	ActTwoSize = 99 + ActTwoPayloadSize

	// ActThreeSize is the size of the packet sent from initiator to
	// responder in ActThree. The packet consists of a handshake version,
	// the initiators static key encrypted with strong forward secrecy and
	// a 16-byte poly1035
	// tag.
	//
	// 1 + 33 + 16 + 16
	ActThreeSize = 66
)

// GenActOne generates the initial packet (act one) to be sent from initiator
// to responder. During act one the initiator generates a fresh ephemeral key,
// masks that with the SPAKE2 password, hashes it into the handshake digest,
// and sends that across the wire with an MAC payload with a blank message.
//
//    -> me
func (b *Machine) GenActOne() ([ActOneSize]byte, error) {
	var (
		err    error
		actOne [ActOneSize]byte
	)

	// e
	e, err := b.ephemeralGen()
	if err != nil {
		return actOne, err
	}
	b.localEphemeral = &keychain.PrivKeyECDH{
		PrivKey: e,
	}

	// Mix in the _unmasked_ ephemeral into the transcript hash, as this
	// allows us to use the MAC check to assert if the remote party knows
	// the password or not.
	b.mixHash(b.localEphemeral.PubKey().SerializeCompressed())

	// Now that we have our ephemeral, we'll apply the eke-SPAKE2 specific
	// portion by masking the key with our password.
	maskedEphemeral := ekeMask(b.localEphemeral.PubKey(), b.password)

	maskedEphemeralBytes := maskedEphemeral.SerializeCompressed()

	authPayload := b.EncryptAndHash([]byte{})

	// The initiator sends the minimum handshake version that it will
	//  accept.
	actOne[0] = b.minHandshakeVersion
	copy(actOne[1:34], maskedEphemeralBytes)
	copy(actOne[34:], authPayload)

	// TODO(roasbeef): make ActOne a type, then add methods for writing out
	// to wire

	return actOne, nil
}

// RecvActOne processes the act one packet sent by the initiator. The responder
// executes the mirrored actions to that of the initiator extending the
// handshake digest, unmasking the ephemeral point, and storing the unmasked
// point as the remote ephemeral point.
func (b *Machine) RecvActOne(actOne [ActOneSize]byte) error {
	var (
		err error
		e   [33]byte
		p   [16]byte
	)

	// If the handshake version is unknown, then the handshake fails
	// immediately. If the handshake version is unknown or no longer
	// supported, then the handshake fails immediately.
	if actOne[0] < b.minHandshakeVersion ||
		actOne[0] > b.maxHandshakeVersion {

		return fmt.Errorf("act one: invalid handshake version: %v, "+
			"only versions between %v and %v are valid, msg=%x",
			actOne[0], b.minHandshakeVersion,
			b.maxHandshakeVersion, actOne[:])
	}

	copy(e[:], actOne[1:34])
	copy(p[:], actOne[34:])

	// me
	maskedEphemeral, err := btcec.ParsePubKey(e[:], btcec.S256())
	if err != nil {
		return err
	}

	// Turn the masked ephemeral into a normal point, and store that as the
	// remote ephemeral key.
	b.remoteEphemeral = ekeUnmask(maskedEphemeral, b.password)

	// We mix in this _unmasked_ point as otherwise we will fail the MC
	// check below if we didn't recover the correct point.
	b.mixHash(b.remoteEphemeral.SerializeCompressed())

	// If we received the wrong unmasked key, then this operation should
	// fail.
	_, err = b.DecryptAndHash(p[:])
	return err
}

// GenActTwo generates the second packet (act two) to be sent from the
// responder to the initiator. Assuming the responder was able to properly
// unmask the point and check the MAC, then this progresses the handshake by
// sending over a new ephemeral, performing ecdh with that, sending over a
// static key, and then performing ecdh between that key and the ephemera.
//
//    <- e, ee, s, es
func (b *Machine) GenActTwo() ([ActTwoSize]byte, error) {
	var (
		err    error
		actTwo [ActTwoSize]byte
	)

	// e
	e, err := b.ephemeralGen()
	if err != nil {
		return actTwo, err
	}
	b.localEphemeral = &keychain.PrivKeyECDH{
		PrivKey: e,
	}

	ephemeral := b.localEphemeral.PubKey().SerializeCompressed()
	b.mixHash(b.localEphemeral.PubKey().SerializeCompressed())

	// ee
	ee, err := ecdh(b.remoteEphemeral, b.localEphemeral)
	if err != nil {
		return actTwo, err
	}
	b.mixKey(ee)

	// s
	ourPubkey := b.localStatic.PubKey().SerializeCompressed()
	ciphertext := b.EncryptAndHash(ourPubkey)

	// es
	es, err := ecdh(b.remoteEphemeral, b.localStatic)
	if err != nil {
		return actTwo, err
	}
	b.mixKey(es)

	// At this point, we've authenticated the responder, and need to carry
	// out the final step primarily to obtain their long-term public key
	// and initialize the DH handshake.
	//
	// However, if we are using HandshakeVersion 0, we also want to send the
	// client data they may need for authentication (if present) encrypted
	// with strong forward secrecy.
	var payload [ActTwoPayloadSize]byte
	if b.handshakeVersion == HandshakeVersion0 && b.authData != nil {
		// If we have an auth payload, then we'll write out 2 bytes
		// that denotes the true length of the payload, followed by the
		// payload itself.
		var payloadWriter bytes.Buffer

		var length [2]byte
		payLoadlen := len(b.authData)
		binary.BigEndian.PutUint16(length[:], uint16(payLoadlen))

		if _, err := payloadWriter.Write(length[:]); err != nil {
			return actTwo, err
		}
		if _, err := payloadWriter.Write(b.authData); err != nil {
			return actTwo, err
		}

		copy(payload[:], payloadWriter.Bytes())
	}

	authPayload := b.EncryptAndHash(payload[:])

	// The responder will always send its preferred handshake version in
	// the hopes that the initiator will then upgrade to this version in
	// act 3.
	actTwo[0] = b.handshakeVersion
	copy(actTwo[1:34], ephemeral)
	copy(actTwo[34:], ciphertext)
	copy(actTwo[83:], authPayload)

	return actTwo, nil
}

// RecvActTwo processes the second packet (act two) sent from the responder to
// the initiator. A successful processing of this packet presents the initiator
// with the responder's public key, and sets us up for the final leg of the
// triple diffie hellman.
func (b *Machine) RecvActTwo(actTwo [ActTwoSize]byte) error {
	var (
		err error
		e   [33]byte
		s   [33 + 16]byte
		p   [ActTwoPayloadSize + 16]byte
	)

	// If the handshake version is unknown, then the handshake fails
	// immediately.
	responderVersion := actTwo[0]
	if responderVersion < b.minHandshakeVersion ||
		responderVersion > b.maxHandshakeVersion {

		return fmt.Errorf("act two: invalid handshake version: %v, "+
			"only versions between %v and %v are valid, msg=%x",
			responderVersion, b.minHandshakeVersion,
			b.maxHandshakeVersion, actTwo[:])
	}

	// The version that the responder sent over is the latest version that
	// they support, so we will continue with this version.
	b.handshakeVersion = responderVersion

	copy(e[:], actTwo[1:34])
	copy(s[:], actTwo[34:83])
	copy(p[:], actTwo[83:])

	// e
	b.remoteEphemeral, err = btcec.ParsePubKey(e[:], btcec.S256())
	if err != nil {
		return err
	}
	b.mixHash(b.remoteEphemeral.SerializeCompressed())

	// ee
	ee, err := ecdh(b.remoteEphemeral, b.localEphemeral)
	if err != nil {
		return err
	}
	b.mixKey(ee)

	// s
	remotePub, err := b.DecryptAndHash(s[:])
	if err != nil {
		return err
	}
	b.remoteStatic, err = btcec.ParsePubKey(remotePub, btcec.S256())
	if err != nil {
		return err
	}

	// es
	es, err := ecdh(b.remoteStatic, b.localEphemeral)
	if err != nil {
		return err
	}
	b.mixKey(es)

	// The payload sent during this second act by the responder is to be
	// interpreted as an additional piece of authentication information.
	payload, err := b.DecryptAndHash(p[:])
	if err != nil {
		return err
	}

	// If the payload is a non-zero length, then we'll assume it's the auth
	// data and attempt to fully decode it.
	if len(payload) == 0 {
		return err
	}

	payloadLen := binary.BigEndian.Uint16(payload[:2])
	b.authData = make([]byte, payloadLen)

	payloadReader := bytes.NewReader(payload[2:])
	if _, err := payloadReader.Read(b.authData); err != nil {
		return err
	}

	return err
}

// GenActThree creates the final (act three) packet of the handshake. Act three
// is to be sent from the initiator to the responder. The purpose of act three
// is to transmit the initiator's public key under strong forward secrecy to
// the responder. This act also includes the final ECDH operation which yields
// the final session.
//
//    -> s, se
func (b *Machine) GenActThree() ([ActThreeSize]byte, error) {
	var actThree [ActThreeSize]byte

	// s
	ourPubkey := b.localStatic.PubKey().SerializeCompressed()
	ciphertext := b.EncryptAndHash(ourPubkey)

	// se
	se, err := ecdh(b.remoteEphemeral, b.localStatic)
	if err != nil {
		return actThree, err
	}
	b.mixKey(se)

	authPayload := b.EncryptAndHash([]byte{})

	actThree[0] = b.handshakeVersion
	copy(actThree[1:50], ciphertext)
	copy(actThree[50:], authPayload)

	// With the final ECDH operation complete, derive the session sending
	// and receiving keys.
	b.split()

	return actThree, nil
}

// RecvActThree processes the final act (act three) sent from the initiator to
// the responder. After processing this act, the responder learns of the
// initiator's static public key. Decryption of the static key serves to
// authenticate the initiator to the responder.
func (b *Machine) RecvActThree(actThree [ActThreeSize]byte) error {
	var (
		err error
		s   [33 + 16]byte
		p   [16]byte
	)

	// If the handshake version is unknown, then the handshake fails
	// immediately. At this point, we expect the initiator to agree with
	// our current handshake version that we sent over in act 2.
	if actThree[0] != b.handshakeVersion {
		return fmt.Errorf("act three: invalid handshake version: %v, "+
			"only %v is valid, msg=%x", actThree[0],
			b.maxHandshakeVersion, actThree[:])
	}

	copy(s[:], actThree[1:33+16+1])
	copy(p[:], actThree[33+16+1:])

	// s
	remotePub, err := b.DecryptAndHash(s[:])
	if err != nil {
		return err
	}
	b.remoteStatic, err = btcec.ParsePubKey(remotePub, btcec.S256())
	if err != nil {
		return err
	}

	// se
	se, err := ecdh(b.remoteStatic, b.localEphemeral)
	if err != nil {
		return err
	}
	b.mixKey(se)

	if _, err := b.DecryptAndHash(p[:]); err != nil {
		return err
	}

	// With the final ECDH operation complete, derive the session sending
	// and receiving keys.
	b.split()

	return nil
}

// WriteAuthData appends a length prefix to the authData and sends it in chunks
// on the wire.
func (b *Machine) WriteAuthData(w io.Writer) error {
	payloadLen := uint32(len(b.authData))
	if payloadLen > maxAuthDataPayloadSize {
		return fmt.Errorf("payload size of %d exceeds the maximum "+
			"aload size of %d", payloadLen, maxAuthDataPayloadSize)
	}

	// Concatenate the length prefix and the payload.
	data := make([]byte, authDataLengthSize+len(b.authData))
	binary.BigEndian.PutUint32(data[:authDataLengthSize], payloadLen)
	copy(data[authDataLengthSize:], b.authData)

	var (
		done         bool
		payload      []byte
		offset       int
		maxChunkSize = math.MaxUint16
	)
	for !done {
		payload = data[offset:]
		if len(payload) < maxChunkSize {
			done = true
		} else {
			payload = data[offset : offset+maxChunkSize]
			offset += maxChunkSize
		}

		if err := b.WriteMessage(payload); err != nil {
			return err
		}

		if _, err := b.Flush(w); err != nil {
			return err
		}
	}

	return nil
}

// ReadAuthData reads authData in chunks from the wire. It expects the first
// authDataLengthSize bytes to define the length of the authData payload to
// follow.
func (b *Machine) ReadAuthData(r io.Reader) error {
	chunk, err := b.ReadMessage(r)
	if err != nil {
		return err
	}

	if len(chunk) < authDataLengthSize {
		return fmt.Errorf("auth data length is expected to be "+
			"encoded in a %d byte prefix", authDataLengthSize)
	}

	// First, read the size of the authData to follow and ensure that it is
	// a sane size.
	payloadLen := binary.BigEndian.Uint32(chunk[:authDataLengthSize])
	if payloadLen > maxAuthDataPayloadSize {
		return fmt.Errorf("auth data length of %d exceeds the "+
			"maximum sane length of %d", payloadLen,
			maxAuthDataPayloadSize)
	}

	offset := len(chunk) - authDataLengthSize
	authData := make([]byte, payloadLen)
	copy(authData[:offset], chunk[authDataLengthSize:])

	var nextOffset int
	for uint32(offset) < payloadLen {
		chunk, err = b.ReadMessage(r)
		if err != nil {
			return err
		}

		nextOffset = offset + len(chunk)
		copy(authData[offset:nextOffset], chunk)
		offset = nextOffset
	}

	b.authData = authData
	return nil
}

// split is the final wrap-up act to be executed at the end of a successful
// three act handshake. This function creates two internal cipherState
// instances: one which is used to encrypt messages from the initiator to the
// responder, and another which is used to encrypt message for the opposite
// direction.
func (b *Machine) split() {
	var (
		empty   []byte
		sendKey [32]byte
		recvKey [32]byte
	)

	h := hkdf.New(sha256.New, empty, b.chainingKey[:], empty)

	// If we're the initiator the first 32 bytes are used to encrypt our
	// messages and the second 32-bytes to decrypt their messages. For the
	// responder the opposite is true.
	if b.initiator {
		_, _ = h.Read(sendKey[:])
		b.sendCipher = cipherState{}
		b.sendCipher.InitializeKeyWithSalt(b.chainingKey, sendKey)

		_, _ = h.Read(recvKey[:])
		b.recvCipher = cipherState{}
		b.recvCipher.InitializeKeyWithSalt(b.chainingKey, recvKey)
	} else {
		_, _ = h.Read(recvKey[:])
		b.recvCipher = cipherState{}
		b.recvCipher.InitializeKeyWithSalt(b.chainingKey, recvKey)

		_, _ = h.Read(sendKey[:])
		b.sendCipher = cipherState{}
		b.sendCipher.InitializeKeyWithSalt(b.chainingKey, sendKey)
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
	b.nextHeaderSend = b.sendCipher.Encrypt(nil, nil, pktLen[:])

	// Finally, generate the encrypted packet itself.
	b.nextBodySend = b.sendCipher.Encrypt(nil, nil, p)

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
	pktLenBytes, err := b.recvCipher.Decrypt(
		nil, nil, b.nextCipherHeader[:],
	)
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
	return b.recvCipher.Decrypt(nil, nil, buf)
}
