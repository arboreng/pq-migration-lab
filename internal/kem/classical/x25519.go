// Package classical implements agility.KEMFactory for classical
// (pre-quantum) key exchange, modeled as a KEM: Encapsulate generates an
// ephemeral keypair and runs ECDH against the peer's public key, treating
// the ephemeral public key as the "ciphertext".
package classical

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

// X25519Name is the algorithm identifier registered for this KEM.
const X25519Name = "X25519"

type x25519Factory struct{}

var (
	_ agility.KEMFactory = x25519Factory{}
	_ agility.KEMSession = (*x25519Session)(nil)
)

// NewX25519 returns the X25519 KEMFactory.
func NewX25519() agility.KEMFactory { return x25519Factory{} }

func (x25519Factory) Name() string           { return X25519Name }
func (x25519Factory) Family() agility.Family { return agility.FamilyKEM }
func (x25519Factory) New() (agility.KEMSession, error) {
	return &x25519Session{}, nil
}

type x25519Session struct {
	priv *ecdh.PrivateKey
}

func (s *x25519Session) GenerateKeyPair() ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.priv = priv
	return priv.PublicKey().Bytes(), nil
}

func (s *x25519Session) Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	peerPub, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err = ephemeral.ECDH(peerPub)
	if err != nil {
		return nil, nil, err
	}
	return ephemeral.PublicKey().Bytes(), sharedSecret, nil
}

func (s *x25519Session) Decapsulate(ciphertext []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("classical: Decapsulate called before GenerateKeyPair")
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ciphertext)
	if err != nil {
		return nil, err
	}
	return s.priv.ECDH(ephemeralPub)
}

func (s *x25519Session) Close() error { return nil }
