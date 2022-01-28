package noise

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type symmetricState struct {
	cipherState

	// ck is used as the salt to the HKDF function to derive a new chaining
	// key as well as a new tempKey which is used for encryption/decryption.
	ck [32]byte

	// tempKey is the latter 32 bytes resulted from the latest HKDF
	// iteration. This key is used to encrypt/decrypt any handshake
	// messages or payloads sent until the next DH operation is executed.
	tempKey [32]byte

	// h is the cumulative hash digest of all handshake messages sent from
	// start to finish. This value is never transmitted to the other side,
	// but will be used as the AD when encrypting/decrypting messages using
	// our AEAD construction.
	h [32]byte
}

// InitializeSymmetric initializes the symmetric state by setting the handshake
// digest (h) and the chaining key (ck) to protocol Name.
func (s *symmetricState) InitializeSymmetric(protocolName []byte) {
	var empty [32]byte

	s.h = sha256.Sum256(protocolName)
	s.ck = s.h
	s.InitializeKey(empty)
}

// mixKey is implements a basic HKDF-based key ratchet. This method is called
// with the result of each DH output generated during the handshake process.
// The first 32 bytes extract from the HKDF reader is the next chaining key,
// then latter 32 bytes become the temp secret key using within any future AEAD
// operations until another DH operation is performed.
func (s *symmetricState) mixKey(input []byte) {
	var info []byte

	secret := input
	salt := s.ck
	h := hkdf.New(sha256.New, secret, salt[:], info)

	// hkdf(ck, input, zero)
	// |
	// | \
	// |  \
	// ck  k
	_, _ = h.Read(s.ck[:])
	_, _ = h.Read(s.tempKey[:])

	// cipher.k = temp_key
	s.InitializeKey(s.tempKey)
}

// mixHash hashes the passed input data into the cumulative handshake digest.
// The running result of this value (h) is used as the associated data in all
// decryption/encryption operations.
func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	_, _ = h.Write(s.h[:])
	_, _ = h.Write(data)

	copy(s.h[:], h.Sum(nil))
}

// EncryptAndHash returns the authenticated encryption of the passed plaintext.
// When encrypting the handshake digest (h) is used as the associated data to
// the AEAD cipher.
func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	ciphertext := s.Encrypt(s.h[:], plaintext)

	s.mixHash(ciphertext)

	return ciphertext
}

// DecryptAndHash returns the authenticated decryption of the passed
// ciphertext.  When encrypting the handshake digest (h) is used as the
// associated data to the AEAD cipher.
func (s *symmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.Decrypt(s.h[:], ciphertext)
	if err != nil {
		return nil, err
	}

	s.mixHash(ciphertext)

	return plaintext, nil
}
