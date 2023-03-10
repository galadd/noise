package state

import (
	"bytes"
	"testing"
)

func TestCipherState_Initialize(t *testing.T) {
	cs := CipherState{}
	// create a byte key value with inputs
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cs.InitializeKey(key)

	if !bytes.Equal(cs.k[:], key) {
		t.Errorf("Key is not equal")
	}

	if cs.n != 0 {
		t.Errorf("Nonce is not 0")
	}
}

func TestCipherState_SetNonce(t *testing.T) {
	cs := CipherState{}
	// create a byte key value with inputs
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cs.InitializeKey(key)

	cs.SetNonce(100)

	if cs.n != 100 {
		t.Errorf("Nonce is not 100")
	}
}

func TestCipherState_EncryptWithAd(t *testing.T) {
	cs := CipherState{}
	// create a byte key value with inputs
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cs.InitializeKey(key)

	ad := []byte("this is an ad")
	plaintext := []byte("hello world")

	ciphertext, err := cs.EncryptWithAd(ad, plaintext)

	if err != nil {
		t.Errorf("Error encrypting plaintext: %s", err)
	}

	if len(ciphertext) != len(plaintext)+16 {
		t.Errorf("Ciphertext length is not %d bytes", len(plaintext)+16)
	}
}

func TestCipherState_DecryptWithAd(t *testing.T) {
	cs := CipherState{}
	// create a byte key value with inputs
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cs.InitializeKey(key)

	ad := []byte("this is an ad")
	plaintext := []byte("hello world")

	ciphertext, _ := cs.EncryptWithAd(ad, plaintext)

	decryptedPlaintext, err := cs.DecryptWithAd(ad, ciphertext)

	if err != nil {
		t.Errorf("Error decrypting ciphertext: %s", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Errorf("Plaintexts are not equal")
	}
}