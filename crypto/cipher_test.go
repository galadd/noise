package crypto

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := [32]byte{}
	n := uint64(0)
	ad := []byte{}
	plaintext := []byte("hello world")
	ciphertext, err := Encrypt(key, n, ad, plaintext)
	if err != nil {
		t.Errorf("Error encrypting plaintext: %s", err)
	}

	if len(ciphertext) != len(plaintext)+16 {
		t.Errorf("Ciphertext length is not %d bytes", len(plaintext)+16)
	}
}

func TestDecrypt(t *testing.T) {
	key := [32]byte{}
	n := uint64(0)
	ad := []byte{}
	plaintext := []byte("hello world")
	ciphertext, _ := Encrypt(key, n, ad, plaintext)

	decryptedPlaintext, err := Decrypt(key, n, ad, ciphertext)
	if err != nil {
		t.Errorf("Error decrypting ciphertext: %s", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Errorf("Plaintexts are not equal")
	}
}