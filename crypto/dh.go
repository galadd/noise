package crypto

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/curve25519"
)

// specifying the size in bytes of public keys and DH output
const DHLEN = 32

/*
 * KeyPair struct for holding private and public keys
 */
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

/*
 * GenerateKeypair generates a new keypair
 */
func GenerateKeypair() (*KeyPair, error) {
	var keyPair KeyPair

	if _, err := rand.Read(keyPair.PrivateKey[:]); err != nil {
		err = errors.New("Error generating keypair")
		return nil, err
	}

	curve25519.ScalarBaseMult(&keyPair.PublicKey, &keyPair.PrivateKey)

	return &keyPair, nil
}

/*
 * DH performs a Diffie-Hellman key exchange and returns the shared key
 */
func DH(publicKey1, publicKey2 []byte) ([]byte, error) {
	sharedKey, err := curve25519.X25519(publicKey1, publicKey2)
	if err != nil {
		err = errors.New("Error generating shared key")
		return nil, err
	}

	return sharedKey, err
}

