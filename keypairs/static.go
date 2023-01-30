package keypairs

import (
	"crypto/ed25519"
)

func StaticKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	return publicKey, privateKey
}