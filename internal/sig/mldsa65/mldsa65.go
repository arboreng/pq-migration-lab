// Package mldsa65 implements agility.SignatureFactory for post-quantum
// signatures, backed by liboqs via the liboqs-go cgo bindings (same
// requirements as internal/kem/mlkem768: liboqs must be discoverable via
// pkg-config: see docker/Dockerfile).
package mldsa65

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

// MLDSA65Name is the algorithm identifier registered for this signature
// scheme, and the exact liboqs algorithm name passed to oqs.Signature.Init.
const MLDSA65Name = "ML-DSA-65"

type mldsa65Factory struct{}

var (
	_ agility.SignatureFactory = mldsa65Factory{}
	_ agility.SignatureSession = (*mldsa65Session)(nil)
)

// NewMLDSA65 returns the ML-DSA-65 SignatureFactory.
func NewMLDSA65() agility.SignatureFactory { return mldsa65Factory{} }

func (mldsa65Factory) Name() string           { return MLDSA65Name }
func (mldsa65Factory) Family() agility.Family { return agility.FamilySignature }

func (mldsa65Factory) New() (agility.SignatureSession, error) {
	sig := new(oqs.Signature)
	if err := sig.Init(MLDSA65Name, nil); err != nil {
		return nil, err
	}
	return &mldsa65Session{sig: sig}, nil
}

type mldsa65Session struct {
	sig *oqs.Signature
}

func (s *mldsa65Session) GenerateKeyPair() ([]byte, error) {
	return s.sig.GenerateKeyPair()
}

func (s *mldsa65Session) Sign(message []byte) ([]byte, error) {
	return s.sig.Sign(message)
}

func (s *mldsa65Session) Verify(message, signature, publicKey []byte) (bool, error) {
	return s.sig.Verify(message, signature, publicKey)
}

func (s *mldsa65Session) Close() error {
	s.sig.Clean()
	return nil
}
