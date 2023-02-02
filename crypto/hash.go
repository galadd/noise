package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	Hashlen = 32
	Blocklen = 64
)

func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func HashHMAC(key, data []byte) []byte {
	hash := sha256.New
	mac := hmac.New(hash, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func Hkdf(chainingKey, inputKeyMaterial []byte, numOutputs uint8) ([][][]byte, error) {

	if numOutputs != 2 && numOutputs != 3 {
		return nil, errors.New("numOutputs must be 2 or 3")
	}

	tempKey := HashHMAC(chainingKey, inputKeyMaterial)
	output1 := HashHMAC(tempKey, []byte{1})
	output2 := HashHMAC(tempKey, append(output1, 2))

	if numOutputs == 2 {
		return [][][]byte{[][]byte{output1, output2}}, nil
	} else {
		output3 := HashHMAC(tempKey, append(output2, 3))
		return [][][]byte{[][]byte{output1, output2, output3}}, nil
	}
}