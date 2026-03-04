// Package pq implements agility.KEMFactory for post-quantum key exchange,
// backed by liboqs via the liboqs-go cgo bindings. Building or testing this
// package requires liboqs's headers/libs to be discoverable via pkg-config
// (see docker/Dockerfile, which builds and wires this up).
package pq

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

// MLKEM768Name is the algorithm identifier registered for this KEM, and the
// exact liboqs algorithm name passed to oqs.KeyEncapsulation.Init.
const MLKEM768Name = "ML-KEM-768"

type mlkem768Factory struct{}

var (
	_ agility.KEMFactory = mlkem768Factory{}
	_ agility.KEMSession = (*mlkem768Session)(nil)
)

// NewMLKEM768 returns the ML-KEM-768 KEMFactory.
func NewMLKEM768() agility.KEMFactory { return mlkem768Factory{} }

func (mlkem768Factory) Name() string           { return MLKEM768Name }
func (mlkem768Factory) Family() agility.Family { return agility.FamilyKEM }

func (mlkem768Factory) New() (agility.KEMSession, error) {
	kem := new(oqs.KeyEncapsulation)
	if err := kem.Init(MLKEM768Name, nil); err != nil {
		return nil, err
	}
	return &mlkem768Session{kem: kem}, nil
}

type mlkem768Session struct {
	kem *oqs.KeyEncapsulation
}

func (s *mlkem768Session) GenerateKeyPair() ([]byte, error) {
	return s.kem.GenerateKeyPair()
}

func (s *mlkem768Session) Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	return s.kem.EncapSecret(peerPublicKey)
}

func (s *mlkem768Session) Decapsulate(ciphertext []byte) ([]byte, error) {
	return s.kem.DecapSecret(ciphertext)
}

func (s *mlkem768Session) Close() error {
	s.kem.Clean()
	return nil
}
