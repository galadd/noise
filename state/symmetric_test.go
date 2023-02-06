package state

import (
	"bytes"
	"testing"
)

func TestSymmetricState_InitializeSymmetric(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)

	if ss.ck != ss.h {
		t.Errorf("SymmetricState.ck != SymmetricState.h")
	}

	if ss.cs.k != [32]byte{} {
		t.Errorf("SymmetricState.cs.k != [32]byte{}")
	}

	if ss.cs.n != 0 {
		t.Errorf("SymmetricState.cs.n != 0")
	}
}

func TestSymmetricState_MixKey(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)

	key1 := ss.cs.k

	inputKeyMaterial := []byte("hello world")
	ss.MixKey(inputKeyMaterial)

	key2 := ss.cs.k

	if bytes.Equal(key1[:], key2[:]) {
		t.Errorf("key1 should not equal key2")
	}
}

func TestSymmetricState_MixHash(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)

	h1 := ss.GetHandshakeHash()

	data := []byte("hello world")
	ss.MixHash(data)

	h2 := ss.GetHandshakeHash()

	if h1 == h2 {
		t.Errorf("h1 should not equal h2")
	}	
}	

func TestSymmetricState_MixKeyAndHash(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)

	key1 := ss.cs.k
	hash1 := ss.GetHandshakeHash()

	inputKeyMaterial := []byte("hello world")
	ss.MixKeyAndHash(inputKeyMaterial)

	key2 := ss.cs.k
	hash2 := ss.GetHandshakeHash()

	if bytes.Equal(key1[:], key2[:]) {
		t.Errorf("key1 should not equal key2")
	}

	if hash1 == hash2 {
		t.Errorf("hash1 should not equal hash2")
	}
}

func TestSymmetricState_EncryptAndHash(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)
	ss.cs.InitializeKey([]byte("key"))

	data := []byte("hello world")
	ciphertext, err := ss.EncryptAndHash(data)
	if err != nil {
		t.Errorf("Error encrypting data: %s", err)
	}

	if len(ciphertext) != len(data) + 16 {
		t.Errorf("Ciphertext length is not %d bytes", len(data)+16)
	}
}

func TestSymmetricState_DecryptAndHash(t *testing.T) {
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	ss := SymmetricState{}
	ss.InitializeSymmetric(protocolName)
	ss.cs.InitializeKey([]byte("key"))

	data := []byte("hello world")
	ciphertext, _ := ss.EncryptAndHash(data)

	decryptedData, err := ss.DecryptAndHash(ciphertext)
	if err != nil {
		t.Errorf("Error decrypting ciphertext: %s", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Data is not equal")
	}
}