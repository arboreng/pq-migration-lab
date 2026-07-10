package ed25519

import "testing"

func TestEd25519SignVerifyRoundTrip(t *testing.T) {
	factory := NewEd25519()
	signer, err := factory.New()
	if err != nil {
		t.Fatalf("New() (signer) returned unexpected error: %v", err)
	}
	defer func() { _ = signer.Close() }()

	pub, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() returned unexpected error: %v", err)
	}

	message := []byte("pq-migration-lab signature demo")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() returned unexpected error: %v", err)
	}

	verifier, err := factory.New()
	if err != nil {
		t.Fatalf("New() (verifier) returned unexpected error: %v", err)
	}
	defer func() { _ = verifier.Close() }()

	valid, err := verifier.Verify(message, signature, pub)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("Verify() = false, want true for an untampered signature")
	}
}

func TestEd25519VerifyRejectsTampering(t *testing.T) {
	factory := NewEd25519()
	signer, err := factory.New()
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	defer func() { _ = signer.Close() }()

	pub, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() returned unexpected error: %v", err)
	}

	message := []byte("pq-migration-lab signature demo")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() returned unexpected error: %v", err)
	}

	verifier, err := factory.New()
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	defer func() { _ = verifier.Close() }()

	tamperedMessage := []byte("pq-migration-lab signature deno")
	if valid, err := verifier.Verify(tamperedMessage, signature, pub); err != nil || valid {
		t.Fatalf("Verify() with tampered message = (%v, %v), want (false, nil)", valid, err)
	}

	tamperedSig := append([]byte{}, signature...)
	tamperedSig[0] ^= 0xFF
	if valid, err := verifier.Verify(message, tamperedSig, pub); err != nil || valid {
		t.Fatalf("Verify() with tampered signature = (%v, %v), want (false, nil)", valid, err)
	}
}

func TestEd25519SignBeforeGenerateKeyPair(t *testing.T) {
	factory := NewEd25519()
	signer, err := factory.New()
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	defer func() { _ = signer.Close() }()

	if _, err := signer.Sign([]byte("too soon")); err == nil {
		t.Fatal("Sign() before GenerateKeyPair(): expected error, got nil")
	}
}
