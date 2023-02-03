package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

/*
 * Hashlen is the length of the hash output.
 * Blocklen is the length of the block input.
 */
const (
	Hashlen = 32
	Blocklen = 64
)

/*
 * Hash hashes the data with SHA256.
 */
func Hash(data []byte) [Hashlen]byte {
	hash := sha256.Sum256(data)
	return hash
}

/*
 * HashHMAC performs the HMAC-SHA256 function.
 */
func HashHMAC(key, data []byte) []byte {
	hash := sha256.New
	mac := hmac.New(hash, key)
	mac.Write(data)
	return mac.Sum(nil)
}

/*
 * Hkdf performs the HKDF key derivation function.
 */
func Hkdf(chainingKey, inputKeyMaterial []byte, numOutputs uint8) ([]byte, []byte, []byte, error) {
	if numOutputs != 2 && numOutputs != 3 {
		return nil, nil, nil, errors.New("numOutputs must be 2 or 3")
	}

	tempKey := HashHMAC(chainingKey, inputKeyMaterial)
	output1 := HashHMAC(tempKey, []byte{1})
	output2 := HashHMAC(tempKey, append(output1, 2))

	if numOutputs == 2 {
		return output1, output2, nil, nil
	} else {
		output3 := HashHMAC(tempKey, append(output2, 3))
		return output1, output2, output3, nil
	}
}