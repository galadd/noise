package xx

import (
	"crypto/ed25519"
	"testing"

	"github.com/galadd/noise/keypairs"
)

type User struct {
	publicKey ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

var sender *User
var plaintext []byte
var ciphertext []byte
var sig []byte

func Test_Sendencryptedmessage(t *testing.T) {
	staticPubKey, staticPrivKey := keypairs.StaticKeyPair()

	sender = &User{
		publicKey: staticPubKey,
		privateKey: staticPrivKey,
	}

	secretKey := []byte("12345678901234567890123456789012")

	plaintext = []byte("Hello, world!")

	ciphertext1, sign, err := SendEncryptedMessage(sender.privateKey, secretKey, plaintext)
	if err != nil {
		t.Errorf("SendEncryptedMessage() returned error: %v", err)
	}

	if ciphertext1 == nil {
		t.Errorf("SendEncryptedMessage() returned nil ciphertext")
	}

	if sign == nil {
		t.Errorf("SendEncryptedMessage() returned nil signature")
	}

	ciphertext = ciphertext1
	sig = sign
}

func Test_Receiveencryptedmessage(t *testing.T) {
	secretKey := []byte("12345678901234567890123456789012")

	// receive encrypted message from 1 to 2
	msg, err := ReceiveEncryptedMessage(sender.publicKey, secretKey, sig, ciphertext)
	if err != nil {
		t.Errorf("ReceiveEncryptedMessage() returned error: %v", err)
	}

	if msg == nil {
		t.Errorf("ReceiveEncryptedMessage() returned nil message")
	}

	if string(msg) != string(plaintext) {
		t.Errorf("ReceiveEncryptedMessage() returned wrong message: %v", msg)
	}
}