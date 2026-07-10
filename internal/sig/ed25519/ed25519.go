// Package ed25519 implements agility.SignatureFactory for classical
// (pre-quantum) signatures.
package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

// Ed25519Name is the algorithm identifier registered for this signature scheme.
const Ed25519Name = "Ed25519"

type ed25519Factory struct{}

var (
	_ agility.SignatureFactory = ed25519Factory{}
	_ agility.SignatureSession = (*ed25519Session)(nil)
)

// NewEd25519 returns the Ed25519 SignatureFactory.
func NewEd25519() agility.SignatureFactory { return ed25519Factory{} }

func (ed25519Factory) Name() string           { return Ed25519Name }
func (ed25519Factory) Family() agility.Family { return agility.FamilySignature }
func (ed25519Factory) New() (agility.SignatureSession, error) {
	return &ed25519Session{}, nil
}

type ed25519Session struct {
	priv stded25519.PrivateKey
}

func (s *ed25519Session) GenerateKeyPair() ([]byte, error) {
	pub, priv, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.priv = priv
	return pub, nil
}

func (s *ed25519Session) Sign(message []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("ed25519: Sign called before GenerateKeyPair")
	}
	return stded25519.Sign(s.priv, message), nil
}

func (s *ed25519Session) Verify(message, signature, publicKey []byte) (bool, error) {
	if len(publicKey) != stded25519.PublicKeySize {
		return false, errors.New("ed25519: incorrect public key length")
	}
	return stded25519.Verify(stded25519.PublicKey(publicKey), message, signature), nil
}

func (s *ed25519Session) Close() error { return nil }
