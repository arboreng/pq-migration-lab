package hybrid

import (
	"bytes"
	"errors"
	"testing"

	"github.com/arboreng/pq-migration-lab/internal/agility"
	"github.com/arboreng/pq-migration-lab/internal/kem/mlkem768"
	"github.com/arboreng/pq-migration-lab/internal/kem/x25519"
)

// fakeFactory/fakeSession is a minimal in-memory KEM used to unit-test the
// hybrid combiner's framing and error handling without depending on liboqs.
type fakeFactory struct{ name string }

func (f fakeFactory) Name() string           { return f.name }
func (f fakeFactory) Family() agility.Family { return agility.FamilyKEM }
func (f fakeFactory) New() (agility.KEMSession, error) {
	return &fakeSession{}, nil
}

type fakeSession struct{}

func (s *fakeSession) GenerateKeyPair() ([]byte, error) {
	return []byte("fake-pub"), nil
}

func (s *fakeSession) Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(peerPublicKey) == 0 {
		return nil, nil, errors.New("fake: empty peer public key")
	}
	return []byte("ct-for-" + string(peerPublicKey)), []byte("shared-secret"), nil
}

func (s *fakeSession) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("fake: empty ciphertext")
	}
	return []byte("shared-secret"), nil
}

func (s *fakeSession) Close() error { return nil }

func TestHybridFramingRoundTrip(t *testing.T) {
	factory := NewHybrid(fakeFactory{name: "A"}, fakeFactory{name: "B"})

	if got, want := factory.Name(), "Hybrid(A+B)"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}

	initiator, err := factory.New()
	if err != nil {
		t.Fatalf("New() (initiator) returned unexpected error: %v", err)
	}
	defer func() { _ = initiator.Close() }()

	responder, err := factory.New()
	if err != nil {
		t.Fatalf("New() (responder) returned unexpected error: %v", err)
	}
	defer func() { _ = responder.Close() }()

	pub, err := initiator.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() returned unexpected error: %v", err)
	}

	ciphertext, responderSS, err := responder.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate() returned unexpected error: %v", err)
	}

	initiatorSS, err := initiator.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate() returned unexpected error: %v", err)
	}

	if !bytes.Equal(initiatorSS, responderSS) {
		t.Fatalf("shared secrets don't match: initiator=%x responder=%x", initiatorSS, responderSS)
	}
	if len(initiatorSS) != combinedSecretLen {
		t.Fatalf("combined secret length = %d, want %d", len(initiatorSS), combinedSecretLen)
	}
}

func TestUnframeTruncated(t *testing.T) {
	if _, err := unframe([]byte{0, 0}); err == nil {
		t.Fatal("unframe() with truncated length prefix: expected error, got nil")
	}
	if _, err := unframe(frame([]byte("only-one-part"))); err == nil {
		t.Fatal("unframe() with only one component: expected error, got nil")
	}
	if _, err := unframe(append(frame([]byte("a"), []byte("b")), 0xFF)); err == nil {
		t.Fatal("unframe() with trailing data: expected error, got nil")
	}
}

func TestHybridX25519MLKEM768Integration(t *testing.T) {
	factory := NewHybrid(x25519.NewX25519(), mlkem768.NewMLKEM768())

	initiator, err := factory.New()
	if err != nil {
		t.Fatalf("New() (initiator) returned unexpected error: %v", err)
	}
	defer func() { _ = initiator.Close() }()

	responder, err := factory.New()
	if err != nil {
		t.Fatalf("New() (responder) returned unexpected error: %v", err)
	}
	defer func() { _ = responder.Close() }()

	pub, err := initiator.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() returned unexpected error: %v", err)
	}

	ciphertext, responderSS, err := responder.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate() returned unexpected error: %v", err)
	}

	initiatorSS, err := initiator.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate() returned unexpected error: %v", err)
	}

	if !bytes.Equal(initiatorSS, responderSS) {
		t.Fatalf("shared secrets don't match: initiator=%x responder=%x", initiatorSS, responderSS)
	}
}
