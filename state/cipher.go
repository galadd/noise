package state

import (
	"errors"
	"github.com/galadd/noise/crypto"
)

type CipherState struct {
	k [32]byte
	n uint64
}

func (c *CipherState) InitializeKey(key [32]byte) {
	c.k = key
	c.n = 0
}

func (c *CipherState) HasKey() bool {
	return c.k != [32]byte{}
}

func (c *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	kStatus := c.HasKey()
	if !kStatus {
		return plaintext, errors.New("No key") 
	} else {
		return crypto.Encrypt(c.k, c.n, ad, plaintext)
	}
}

func (c *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	kStatus := c.HasKey()
	if !kStatus {
		return ciphertext, errors.New("No key")
	} else {
		return crypto.Decrypt(c.k, c.n, ad, ciphertext)
	}
}

func (c *CipherState) Rekey() ([32]byte, error) {
	key, err := crypto.Rekey(c.k)
	c.k = key
	return c.k, err
}