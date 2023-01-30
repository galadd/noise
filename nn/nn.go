/*
 * Noise NN Pattern
 * It implements the elliptic curve Diffie-Hellman key exchange to generate a shared secret.
*/
package nn

import (
	"io"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
    "errors"
)

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