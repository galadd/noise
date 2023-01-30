/*
 * Noise NN Pattern
 * It implements the elliptic curve Diffie-Hellman key exchange to generate a shared secret.
*/
package nn

import (
	"io"
	"crypto"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
    "errors"

	"github.com/aead/ecdh"
)

func GenerateKeyPairs(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
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

func PublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
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

func encryptMessage(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func generateMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func SendEncryptedMessage(sharedSecret, plaintext []byte) ([]byte, error) {
	encryptedMessage, err := encryptMessage(sharedSecret, plaintext)
	if err != nil {
		return nil, err
	}

	mac := generateMAC(sharedSecret, encryptedMessage)
	return append(encryptedMessage, mac...), nil
}

func decryptMessage(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func verifyMAC(key, message, expectedMAC []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hmac.Equal(mac.Sum(nil), expectedMAC)
}

func ReceiveEncryptedMessage(sharedSecret, encryptedMessage []byte) ([]byte, error) {
	macSize := sha256.Size
	encryptedMessage, mac := encryptedMessage[:len(encryptedMessage)-macSize], encryptedMessage[len(encryptedMessage)-macSize:]
	if !verifyMAC(sharedSecret, encryptedMessage, mac) {
		return nil, errors.New("invalid message authentication code")
	}

	plaintext, err := decryptMessage(sharedSecret, encryptedMessage)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}