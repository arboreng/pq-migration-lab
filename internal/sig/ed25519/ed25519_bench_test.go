package ed25519

import "testing"

var benchMessage = []byte("pq-migration-lab signature benchmark")

func BenchmarkEd25519GenerateKeyPair(b *testing.B) {
	factory := NewEd25519()
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

func BenchmarkEd25519Sign(b *testing.B) {
	factory := NewEd25519()
	signer, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	if _, err := signer.GenerateKeyPair(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sign(benchMessage); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	factory := NewEd25519()
	signer, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	pub, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	signature, err := signer.Sign(benchMessage)
	if err != nil {
		b.Fatal(err)
	}
	verifier, err := factory.New()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = verifier.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(benchMessage, signature, pub); err != nil {
			b.Fatal(err)
		}
	}
}
