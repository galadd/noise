package crypto

import (
	"math"
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
)

/*
 * Encrypt encrypts a plaintext using a key, nonce and associated data
 */
func Encrypt(k [32]byte, n uint64, ad, plaintext []byte) ([]byte, error) {
	codec, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, err
	}

	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], n)
	ciphertext := codec.Seal(nil, append([]byte{0, 0, 0, 0}, nonce[:]...), plaintext, ad)

	return ciphertext, nil
}

/*
 * Decrypt decrypts a ciphertext using a key, nonce and associated data
 */
func Decrypt(k [32]byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	codec, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, err
	}

	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], n)
	plaintext, err := codec.Open(nil, append([]byte{0, 0, 0, 0}, nonce[:]...), ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

/*
 * Rekey generates a new key from an existing key
 */
func Rekey(k [32]byte) ([32]byte, error) {
	var key [32]byte

	encryption, err := Encrypt(k, math.MaxUint64, []byte{}, bytes.Repeat([]byte{0}, 32))
	copy(key[:], encryption[:32])

	return key, err
}