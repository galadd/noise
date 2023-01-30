package keypairs

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func Test_Statickeypair(t *testing.T) {
	publicKey, privateKey := StaticKeyPair()

	if publicKey == nil {
		t.Errorf("StaticKeyPair() returned nil public key")
	}

	if privateKey == nil {
		t.Errorf("StaticKeyPair() returned nil private key")
	}

	publicKey2 := privateKey.Public().(ed25519.PublicKey)

	if publicKey2 == nil {
		t.Errorf("StaticKeyPair() returned nil public key")
	}

	if !bytes.Equal(publicKey, publicKey2) {
		t.Errorf("StaticKeyPair() returned different public keys")
	}
}