package hybrid

import (
	"testing"

	"github.com/arboreng/pq-migration-lab/internal/agility"
	"github.com/arboreng/pq-migration-lab/internal/kem/mlkem768"
	"github.com/arboreng/pq-migration-lab/internal/kem/x25519"
)

func newBenchHybridFactory() agility.KEMFactory {
	return NewHybrid(x25519.NewX25519(), mlkem768.NewMLKEM768())
}

func BenchmarkHybridGenerateKeyPair(b *testing.B) {
	factory := newBenchHybridFactory()
	for i := 0; i < b.N; i++ {
		session, err := factory.New()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := session.GenerateKeyPair(); err != nil {
			b.Fatal(err)
		}
		_ = session.Close()
	}
}

func BenchmarkHybridEncapsulate(b *testing.B) {
	factory := newBenchHybridFactory()
	initiator, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = initiator.Close() }()
	pub, err := initiator.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	responder, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = responder.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := responder.Encapsulate(pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHybridDecapsulate(b *testing.B) {
	factory := newBenchHybridFactory()
	initiator, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = initiator.Close() }()
	pub, err := initiator.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	responder, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = responder.Close() }()
	ciphertext, _, err := responder.Encapsulate(pub)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := initiator.Decapsulate(ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}
