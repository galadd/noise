package xx

import (
	"crypto/ed25519"
	"errors"

	"github.com/galadd/noise/nn"
)

func SendEncryptedMessage(privateKey ed25519.PrivateKey, sharedSecret, plaintext []byte) ([]byte, []byte, error) {
	ciphertext, err := nn.SendEncryptedMessage(sharedSecret, plaintext)
	if err != nil {
		return nil, nil, err
	}

	sig := ed25519.Sign(privateKey, ciphertext)

	return ciphertext, sig, nil
}

func ReceiveEncryptedMessage(publicKey ed25519.PublicKey, sharedSecret, sig, cipher []byte) ([]byte, error) {
	if !ed25519.Verify(publicKey, cipher, sig) {
		return nil, errors.New("signature verification failed")
	}

	plaintext, err := nn.ReceiveEncryptedMessage(sharedSecret, cipher)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}