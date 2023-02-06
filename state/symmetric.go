package state

import (
	"errors"
	"github.com/galadd/noise/crypto"
)

/*
 * SymmetricState is a state object that holds a CipherState, chaining key and hash.
 */
type SymmetricState struct {
	cs CipherState
	ck [crypto.Hashlen]byte
	h  [crypto.Hashlen]byte
}

/*
 * InitializeSymmetric initializes the SymmetricState with a protocol name.
 */
func (s *SymmetricState) InitializeSymmetric(protocolName []byte) {
	if len(protocolName) > crypto.Hashlen {
		errors.New("Protocol name too long")
	}

	if shorter := crypto.Hashlen - len(protocolName); shorter >= 0 {
		protocolName = append(protocolName, make([]byte, shorter)...)
	} else {
		protocolName = protocolName[:crypto.Hashlen]
	}
	s.h = crypto.Hash(protocolName)
	s.ck = s.h
	(s.cs).InitializeKey([]byte{})
}

/*
 * MixKey mixes the inputKeyMaterial into the SymmetricState.
 */
func (s *SymmetricState) MixKey(inputKeyMaterial []byte) {
	ck, tempKey, _, err := crypto.Hkdf(s.ck[:], inputKeyMaterial, 2)
	if err != nil {
		errors.New("Hkdf failed")
	}
	copy(s.ck[:], ck)

	(s.cs).InitializeKey(tempKey)
}

/*
 * MixHash mixes the data into the SymmetricState.
 */
func (s *SymmetricState) MixHash(data []byte) {
	s.h = crypto.Hash(append(s.h[:], data...))
}

/*
 * MixKeyAndHash mixes the inputKeyMaterial into the SymmetricState and
 * mixes the resulting chaining key into the hash.
 */
func (s *SymmetricState) MixKeyAndHash(inputKeyMaterial []byte) {
	ck, tempHash, tempKey, err := crypto.Hkdf(s.ck[:], inputKeyMaterial, 3)
	if err != nil {
		errors.New("Hkdf failed")
	}
	copy(s.ck[:], ck)

	s.MixHash(tempHash)
	(s.cs).InitializeKey(tempKey)
}

/*
 * GetHandshakeHash returns the current hash value.
 */
func (s *SymmetricState) GetHandshakeHash() [crypto.Hashlen]byte {
	return s.h
}

/*
 * EncryptAndHash encrypts the plaintext and mixes the resulting ciphertext
 * into the hash.
 */
func (s *SymmetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := (s.cs).EncryptWithAd(s.h[:], plaintext)
	if err != nil {
		return nil, err
	}
	// s.MixHash(ciphertext) // affects ad in crypto.DecryptWithAd
	return ciphertext, nil
}

/*
 * DecryptAndHash decrypts the ciphertext and mixes the ciphertext into the
 * hash.
 */
func (s *SymmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := (s.cs).DecryptWithAd(s.h[:], ciphertext)
	if err != nil {
		return nil, err
	}

	s.MixHash(ciphertext)
	return plaintext, nil
}

/*
 * Split splits the SymmetricState into two CipherStates.
 */
func (s *SymmetricState) Split() (*CipherState, *CipherState, error) {
	cs1 := new(CipherState)
	cs2 := new(CipherState)

	tempKey1, tempKey2, _, err := crypto.Hkdf(s.ck[:], nil, 2)
	if err != nil {
		return nil, nil, errors.New("Hkdf failed")
	}

	cs1.InitializeKey(tempKey1)
	cs2.InitializeKey(tempKey2)

	return cs1, cs2, nil
}