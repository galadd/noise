// write a test for the nn package
package nn

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func Test_Generatekeypairs(t *testing.T) {
	random := rand.Reader

	privateKey, publicKey, err := GenerateKeyPairs(random)
	if err != nil {
		t.Errorf("GenerateKeyPairs() returned error: %v", err)
	}

	if privateKey == nil {
		t.Errorf("GenerateKeyPairs() returned nil private key")
	}

	if publicKey == nil {
		t.Errorf("GenerateKeyPairs() returned nil public key")
	}
}

func Test_Publickey(t *testing.T) {
	random := rand.Reader

	privateKey, _, err := GenerateKeyPairs(random)
	if err != nil {
		t.Errorf("GenerateKeyPairs() returned error: %v", err)
	}

	publicKey := PublicKey(privateKey)

	if publicKey == nil {
		t.Errorf("PublicKey() returned nil public key")
	}
}

func Test_Check(t *testing.T) {
	random := rand.Reader

	_, publicKey, err := GenerateKeyPairs(random)
	if err != nil {
		t.Errorf("GenerateKeyPairs() returned error: %v", err)
	}

	err = Check(publicKey)
	if err != nil {
		t.Errorf("Check() returned error: %v", err)
	}
}

func Test_Computesecret(t *testing.T) {
	initPrivateKey, initPublicKey, _ := GenerateKeyPairs(nil)
	respPrivateKey, respPublicKey, _ := GenerateKeyPairs(nil)

	sharedSecret := ComputeSecret(initPrivateKey, respPublicKey)
	sharedSecret2 := ComputeSecret(respPrivateKey, initPublicKey)

	if sharedSecret == nil {
		t.Errorf("ComputeSecret() returned nil shared secret")
	}

	if sharedSecret2 == nil {
		t.Errorf("ComputeSecret() returned nil shared secret")
	}

	res := bytes.Compare(sharedSecret, sharedSecret2)
	if res != 0 {
		t.Errorf("ComputeSecret() returned different shared secrets")
	}
}

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
