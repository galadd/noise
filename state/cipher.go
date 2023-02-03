package state

import (
	"errors"
	"github.com/galadd/noise/crypto"
)

/*
 * CipherState is a state object that holds a key and a nonce.
 */
type CipherState struct {
	k [32]byte
	n uint64
}

/*
 * InitializeKey sets the key for the CipherState.
 */
func (c *CipherState) InitializeKey(key []byte) {
	copy(c.k[:], key)
	c.n = 0
}

/*
 * HasKey returns true if the CipherState has a key.
 */
func (c *CipherState) HasKey() bool {
	return c.k != [32]byte{}
}

/*
 * SetNonce sets the nonce for the CipherState.
 */
func (c *CipherState) SetNonce(nonce uint64) {
	c.n = nonce
}

/*
 * EncryptWithAd encrypts the plaintext with associated data ad, key and nonce
 */
func (c *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	kStatus := c.HasKey()
	if !kStatus {
		return plaintext, errors.New("No key") 
	} else {
		ciphertext, err := crypto.Encrypt(c.k, c.n, ad, plaintext)
		// c.n++ // triggers errOpen in ChaCha20Poly1305.Open for some reason
		return ciphertext, err
	}
}

/*
 * DecryptWithAd decrypts the ciphertext with associated data ad, key and nonce
 */
func (c *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	kStatus := c.HasKey()
	if !kStatus {
		return ciphertext, errors.New("No key")
	} else {
		plaintext, err := crypto.Decrypt(c.k, c.n, ad, ciphertext)
		c.n++
		return plaintext, err
	}
}

/*
 * Rekey generates a new key from an existing key
 */
func (c *CipherState) Rekey() ([32]byte, error) {
	key, err := crypto.Rekey(c.k)
	c.k = key
	return c.k, err
}