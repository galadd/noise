// write a test for the nn package
package nn

import (
	"bytes"
	"testing"
)

func Test_Sendencryptedmessage(t *testing.T) {
	secretKey := []byte("12345678901234567890123456789012")

	plaintext := []byte("Hello, world!")

	ciphertext, err := SendEncryptedMessage(secretKey, plaintext)
	if err != nil {
		t.Errorf("SendEncryptedMessage() returned error: %v", err)
	}

	if ciphertext == nil {
		t.Errorf("SendEncryptedMessage() returned nil ciphertext")
	}
}

func Test_Receiveencryptedmessage(t *testing.T) {
	secretKey := []byte("12345678901234567890123456789012")

	plaintext := []byte("Hello, world!")

	ciphertext, _ := SendEncryptedMessage(secretKey, plaintext)
	if ciphertext == nil {
		t.Errorf("SendEncryptedMessage() returned nil ciphertext")
	}

	decrypted, err := ReceiveEncryptedMessage(secretKey, ciphertext)
	if err != nil {
		t.Errorf("ReceiveEncryptedMessage() returned error: %v", err)
	}

	if decrypted == nil {
		t.Errorf("ReceiveEncryptedMessage() returned nil plaintext")
	}

	res := bytes.Compare(plaintext, decrypted)
	if res != 0 {
		t.Errorf("ReceiveEncryptedMessage() returned different plaintext")
	}
}
