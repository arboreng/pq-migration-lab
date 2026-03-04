package pq

import "testing"

func BenchmarkMLKEM768GenerateKeyPair(b *testing.B) {
	factory := NewMLKEM768()
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

func BenchmarkMLKEM768Encapsulate(b *testing.B) {
	factory := NewMLKEM768()
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

func BenchmarkMLKEM768Decapsulate(b *testing.B) {
	factory := NewMLKEM768()
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
