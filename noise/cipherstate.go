package noise

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// keyRotationInterval is the number of messages sent on a single
	// cipher stream before the keys are rotated forwards.
	keyRotationInterval = 1000
)

// cipherState encapsulates the state for the AEAD which will be used to
// encrypt+authenticate any payloads sent during the handshake, and messages
// sent once the handshake has completed. During the handshake phase, each party
// has a single cipherState object but during the transport phase each party has
// two cipherState objects: one for sending and one for receiving.
type cipherState struct {
	// k is the shared symmetric key which will be used to instantiate the
	// cipher.
	k [32]byte

	// n is the nonce passed into the chacha20-poly1305 instance for
	// encryption+decryption. The nonce is incremented after each successful
	// encryption/decryption.
	n uint64

	// salt is an additional secret which is used during key rotation to
	// generate new keys.
	salt [32]byte

	// cipher is an instance of the ChaCha20-Poly1305 AEAD construction
	// created using k above.
	cipher cipher.AEAD
}

func (c *cipherState) InitializeKey(key [32]byte) {
	c.k = key
	c.n = 0

	// Safe to ignore the error here as our key is properly sized
	// (32-bytes).
	c.cipher, _ = chacha20poly1305.New(c.k[:])
}

// InitializeKeyWithSalt is identical to InitializeKey however it also sets the
// cipherState's salt field which is used for key rotation.
func (c *cipherState) InitializeKeyWithSalt(salt, key [32]byte) {
	c.salt = salt
	c.InitializeKey(key)
}

// Encrypt returns a ciphertext which is the encryption of the plainText
// observing the passed associatedData within the AEAD construction. The
// cipher text returned is the same size as the plaintext plus 16 bytes for
// authentication data.
func (c *cipherState) Encrypt(associatedData, plainText []byte) []byte {
	defer func() {
		c.n++

		if c.n == keyRotationInterval {
			c.rotateKey()
		}
	}()

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)

	// TODO(roasbeef): should just return plaintext?

	return c.cipher.Seal(nil, nonce[:], plainText, associatedData)
}

// Decrypt attempts to decrypt the passed ciphertext observing the specified
// associatedData within the AEAD construction. In the case that the final MAC
// check fails, then a non-nil error will be returned.
func (c *cipherState) Decrypt(associatedData, cipherText []byte) ([]byte,
	error) {

	defer func() {
		c.n++

		if c.n == keyRotationInterval {
			c.rotateKey()
		}
	}()

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)

	return c.cipher.Open(nil, nonce[:], cipherText, associatedData)
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

	oldKey := c.k
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
