package keypairs

import (
	"io"
	"crypto"
	"crypto/rand"

	"github.com/aead/ecdh"
)

func EphemeralKeyPairs(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	if random == nil {
		random = rand.Reader
	}

	c25519 := ecdh.X25519()

	privateKey, publicKey, err := c25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func EphemeralPublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	c25519 := ecdh.X25519()

	publicKey := c25519.PublicKey(privateKey)

	return publicKey
}

func Check(publicKey crypto.PublicKey) error {
	c25519 := ecdh.X25519()

	err := c25519.Check(publicKey)
	if err != nil {
		return err
	}

	return nil
}

func ComputeSecret(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) []byte {
	c25519 := ecdh.X25519()

	secret := c25519.ComputeSecret(privateKey, publicKey)

	return secret
}