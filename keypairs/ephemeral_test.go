package keypairs

import (
	"crypto"
	"crypto/rand"
	"bytes"
	"testing"
)

type User struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

var (
	initiator *User
	responder *User
)

func TestEphemeralKeyPairs(t *testing.T) {
	initPrivateKey, initPublicKey, err := EphemeralKeyPairs(rand.Reader)
	if err != nil {
		t.Errorf("EphemeralKeyPairs() returned error: %v", err)
	}

	if initPrivateKey == nil {
		t.Errorf("EphemeralKeyPairs() returned nil privateKey")
	}

	if initPublicKey == nil {
		t.Errorf("EphemeralKeyPairs() returned nil publicKey")
	}

	resPrivateKey, resPublicKey, _ := EphemeralKeyPairs(rand.Reader)

	initiator = &User{
		privateKey: initPrivateKey,
		publicKey:  initPublicKey,
	}

	responder = &User{
		privateKey: resPrivateKey,
		publicKey:  resPublicKey,
	}
}

func TestEphemeralPublicKey(t *testing.T) {
	initPublicKey := EphemeralPublicKey(initiator.privateKey)
	if initPublicKey == nil {
		t.Errorf("EphemeralPublicKey() returned nil publicKey")
	}

	if initPublicKey != initiator.publicKey {
		t.Errorf("EphemeralPublicKey() returned different publicKey")
	}
}

func TestCheck(t *testing.T) {
	err := Check(initiator.publicKey)
	if err != nil {
		t.Errorf("Check() returned error: %v", err)
	}
}

func TestComputeSecret(t *testing.T) {
	initiatorSecret := ComputeSecret(initiator.privateKey, responder.publicKey)
	if initiatorSecret == nil {
		t.Errorf("ComputeSecret() returned nil secret")
	}
	
	responderSecret := ComputeSecret(responder.privateKey, initiator.publicKey)

	res := bytes.Compare(initiatorSecret, responderSecret)
	if res != 0 {
		t.Errorf("ComputeSecret() returned different secret")
	}
}