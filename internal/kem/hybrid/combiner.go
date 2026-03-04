// Package hybrid composes two agility.KEMFactory implementations
// (typically one classical and one post-quantum) into a single hybrid
// KEMFactory. Public keys and ciphertexts from both component KEMs are
// concatenated with a self-describing length prefix (so component sizes
// never need to be hardcoded), and their shared secrets are combined via
// HKDF-SHA384 into a single output secret.
package hybrid

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

const hkdfInfo = "pq-migration-lab hybrid kem v1"

// combinedSecretLen is the output length of the HKDF-SHA384 combiner.
const combinedSecretLen = sha512.Size384

type factory struct {
	a, b agility.KEMFactory
}

var (
	_ agility.KEMFactory = factory{}
	_ agility.KEMSession = (*session)(nil)
)

// NewHybrid returns a KEMFactory that composes a and b.
func NewHybrid(a, b agility.KEMFactory) agility.KEMFactory {
	return factory{a: a, b: b}
}

func (f factory) Name() string {
	return fmt.Sprintf("Hybrid(%s+%s)", f.a.Name(), f.b.Name())
}

func (f factory) Family() agility.Family { return agility.FamilyKEM }

func (f factory) New() (agility.KEMSession, error) {
	sa, err := f.a.New()
	if err != nil {
		return nil, err
	}
	sb, err := f.b.New()
	if err != nil {
		_ = sa.Close()
		return nil, err
	}
	return &session{a: sa, b: sb}, nil
}

type session struct {
	a, b agility.KEMSession
}

func (s *session) GenerateKeyPair() ([]byte, error) {
	pubA, err := s.a.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubB, err := s.b.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return frame(pubA, pubB), nil
}

func (s *session) Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	parts, err := unframe(peerPublicKey)
	if err != nil {
		return nil, nil, err
	}
	ctA, ssA, err := s.a.Encapsulate(parts[0])
	if err != nil {
		return nil, nil, err
	}
	ctB, ssB, err := s.b.Encapsulate(parts[1])
	if err != nil {
		return nil, nil, err
	}
	combined, err := combine(ssA, ssB)
	if err != nil {
		return nil, nil, err
	}
	return frame(ctA, ctB), combined, nil
}

func (s *session) Decapsulate(ciphertext []byte) ([]byte, error) {
	parts, err := unframe(ciphertext)
	if err != nil {
		return nil, err
	}
	ssA, err := s.a.Decapsulate(parts[0])
	if err != nil {
		return nil, err
	}
	ssB, err := s.b.Decapsulate(parts[1])
	if err != nil {
		return nil, err
	}
	return combine(ssA, ssB)
}

func (s *session) Close() error {
	errA := s.a.Close()
	errB := s.b.Close()
	if errA != nil {
		return errA
	}
	return errB
}

// frame concatenates parts, each preceded by a 4-byte big-endian length.
func frame(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p)))
		out = append(out, lenBuf[:]...)
		out = append(out, p...)
	}
	return out
}

// unframe reverses frame, requiring exactly two components.
func unframe(data []byte) ([2][]byte, error) {
	var parts [2][]byte
	for i := 0; i < 2; i++ {
		if len(data) < 4 {
			return parts, errors.New("hybrid: truncated length prefix")
		}
		n := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		if uint64(n) > uint64(len(data)) {
			return parts, errors.New("hybrid: truncated component")
		}
		parts[i] = data[:n]
		data = data[n:]
	}
	if len(data) != 0 {
		return parts, errors.New("hybrid: unexpected trailing data")
	}
	return parts, nil
}

// combine derives a single shared secret from both components' shared
// secrets via HKDF-SHA384.
func combine(ssA, ssB []byte) ([]byte, error) {
	combined := append(append([]byte{}, ssA...), ssB...)
	kdf := hkdf.New(sha512.New384, combined, nil, []byte(hkdfInfo))
	out := make([]byte, combinedSecretLen)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, err
	}
	return out, nil
}
