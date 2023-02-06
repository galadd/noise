package state

import (
	"errors"
	"github.com/galadd/noise/crypto"
	"github.com/galadd/noise/pattern"
)

type HandshakeState struct {
	ss SymmetricState

	s crypto.KeyPair
	e crypto.KeyPair

	rs [32]byte
	re [32]byte

	initiator bool

	messagePatterns []pattern.Messages
}

func (h *HandshakeState) Initialize(handshakePatternName string, initiator bool, prologue []byte, s, e *crypto.KeyPair, rs, re [32]byte) {
	handshakePattern := pattern.HandshakePatterns[handshakePatternName]
	protocolName := []byte("Noise_" + handshakePatternName + "_25519_ChaChaPoly_SHA256")
	h.ss.InitializeSymmetric(protocolName)

	h.ss.MixHash(prologue)

	h.initiator = initiator
	h.s = *s
	h.e = *e
	h.rs = rs
	h.re = re

	for _, token := range handshakePattern.PreMessagePatterns[0] {
		if token == pattern.S {
			if initiator {
				h.ss.MixHash(h.s.PublicKey[:])
			} else {
				h.ss.MixHash(h.rs[:])
			}
		} 
	}

	for _, token := range handshakePattern.PreMessagePatterns[1] {
		if token == pattern.S {
			if initiator {
				h.ss.MixHash(h.rs[:])
			} else {
				h.ss.MixHash(h.s.PublicKey[:])
			}
		}
	}

	h.messagePatterns = handshakePattern.MessagePatterns
}

func (h *HandshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (*CipherState, *CipherState, error) {
	if !h.initiator {
		return nil, nil, errors.New("Turn to read message")
	}

	if len(h.messagePatterns) == 0 {
		return nil, nil, errors.New("Handshake already finished")
	}

	messagePattern := h.messagePatterns[0]
	h.messagePatterns = h.messagePatterns[1:]

	var cs1, cs2 *CipherState

	for _, token := range messagePattern {
		switch token {
		case pattern.E:
			if h.e.PrivateKey != [32]byte{} {
				return nil, nil, errors.New("Ephemeral key must be empty")
			}
			pair, err := crypto.GenerateKeypair()
			if err != nil {
				return nil, nil, err
			}
			h.e = *pair
			*messageBuffer = append(*messageBuffer, h.e.PublicKey[:]...)
			h.ss.MixHash(h.e.PublicKey[:])
		case pattern.S:
			var ctext []byte
			ctext, err := h.ss.EncryptAndHash(h.s.PrivateKey[:])
			if err != nil {
				return nil, nil, err
			}
			*messageBuffer = append(*messageBuffer, ctext...)
		case pattern.EE:
			dhKey, err := crypto.DH(h.e.PrivateKey[:], h.re[:])
			if err != nil {
				return nil, nil, err
			}
			h.ss.MixKey(dhKey[:])
		case pattern.ES:
			if h.initiator {
				dhKey, err := crypto.DH(h.e.PrivateKey[:], h.rs[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			} else {
				dhKey, err := crypto.DH(h.s.PrivateKey[:], h.re[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			}
		case pattern.SE:
			if h.initiator {
				dhKey, err := crypto.DH(h.s.PrivateKey[:], h.re[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			} else {
				dhKey, err := crypto.DH(h.e.PrivateKey[:], h.rs[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			}
		case pattern.SS:
			dhKey, err := crypto.DH(h.s.PrivateKey[:], h.rs[:])
			if err != nil {
				return nil, nil, err
			}
			h.ss.MixKey(dhKey[:])
		}
	}

	var ciphertext []byte
	ciphertext, err := h.ss.EncryptAndHash(payload)
	if err != nil {
		return nil, nil, err
	}
	*messageBuffer = append(*messageBuffer, ciphertext...)

	if len(h.messagePatterns) == 0 {
		cs1, cs2, err = h.ss.Split()
		if err != nil {
			return nil, nil, err
		}
	} 

	h.initiator = !h.initiator

	return cs1, cs2, nil
}

func (h *HandshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (*CipherState, *CipherState, error) {
	if h.initiator {
		return nil, nil, errors.New("Turn to write message")
	}

	if len(h.messagePatterns) == 0 {
		return nil, nil, errors.New("Handshake already finished")
	}

	messagePattern := h.messagePatterns[0]
	h.messagePatterns = h.messagePatterns[1:]

	var temp []byte
	var cs1, cs2 *CipherState
	dhlen := crypto.DHLEN

	for _, token := range messagePattern {
		switch token {
		case pattern.E:
			if h.re != [32]byte{} {
				return nil, nil, errors.New("Ephemeral key must be empty")
			}
			copy(h.re[:], message[:dhlen])
			message = message[dhlen:]
			h.ss.MixHash(h.re[:])
		case pattern.S:	
			if h.ss.cs.HasKey() {
				temp = message[:dhlen + 16]
			} else {
				temp = message[:dhlen]
			}
			message = message[len(temp):]
			plaintext, err := h.ss.DecryptAndHash(temp)
			if err != nil {
				return nil, nil, err
			}
			copy(h.rs[:], plaintext)
		case pattern.EE:
			dhKey, err := crypto.DH(h.e.PrivateKey[:], h.re[:])
			if err != nil {
				return nil, nil, err
			}
			h.ss.MixKey(dhKey[:])
		case pattern.ES:
			if h.initiator {
				dhKey, err := crypto.DH(h.e.PrivateKey[:], h.rs[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			} else {
				dhKey, err := crypto.DH(h.s.PrivateKey[:], h.re[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			}
		case pattern.SE:
			if h.initiator {
				dhKey, err := crypto.DH(h.s.PrivateKey[:], h.re[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			} else {
				dhKey, err := crypto.DH(h.e.PrivateKey[:], h.rs[:])
				if err != nil {
					return nil, nil, err
				}
				h.ss.MixKey(dhKey[:])
			}
		case pattern.SS:
			dhKey, err := crypto.DH(h.s.PrivateKey[:], h.rs[:])
			if err != nil {
				return nil, nil, err
			}
			h.ss.MixKey(dhKey[:])
		}
	}

	plaintext, err := h.ss.DecryptAndHash(message)
	if err != nil {
		return nil, nil, err
	}
	*payloadBuffer = append(*payloadBuffer, plaintext...)

	if len(h.messagePatterns) == 0 {
		cs1, cs2, err = h.ss.Split()
		if err != nil {
			return nil, nil, err
		}
	}

	h.initiator = !h.initiator

	return cs1, cs2, nil
}