package crypto

import (
	"testing"
)

func TestHash(t *testing.T) {
	hash := Hash([]byte("hello world"))
	if len(hash) != Hashlen {
		t.Errorf("Hash length is not %d bytes", Hashlen)
	}
}

func TestHashHMAC(t *testing.T) {
	hash := HashHMAC([]byte("key"), []byte("hello world"))
	if len(hash) != Hashlen {
		t.Errorf("Hash length is not %d bytes", Hashlen)
	}
}

func TestHkdf(t *testing.T) {
	chainingKey := make([]byte, Hashlen)
	inputKeyMaterial := make([]byte, Hashlen)

	output1, output2, output3, err := Hkdf(chainingKey, inputKeyMaterial, 2)
	if err != nil {
		t.Errorf("Error deriving keys: %s", err)
	}

	if len(output1) != Hashlen {
		t.Errorf("Output1 length is not %d bytes", Hashlen)
	}

	if len(output2) != Hashlen {
		t.Errorf("Output2 length is not %d bytes", Hashlen)
	}

	if output3 != nil {
		t.Errorf("Output3 is not nil")
	}

	output1, output2, output3, err = Hkdf(chainingKey, inputKeyMaterial, 3)
	if err != nil {
		t.Errorf("Error deriving keys: %s", err)
	}

	if len(output1) != Hashlen {
		t.Errorf("Output1 length is not %d bytes", Hashlen)
	}

	if len(output2) != Hashlen {
		t.Errorf("Output2 length is not %d bytes", Hashlen)
	}

	if len(output3) != Hashlen {
		t.Errorf("Output3 length is not %d bytes", Hashlen)
	}
}