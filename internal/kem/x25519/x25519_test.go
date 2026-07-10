package x25519

import "testing"

func TestX25519RoundTrip(t *testing.T) {
	factory := NewX25519()

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

	if len(initiatorSS) == 0 || string(initiatorSS) != string(responderSS) {
		t.Fatalf("shared secrets don't match: initiator=%x responder=%x", initiatorSS, responderSS)
	}
}

func TestX25519DecapsulateBeforeGenerate(t *testing.T) {
	factory := NewX25519()
	session, err := factory.New()
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	defer func() { _ = session.Close() }()

	if _, err := session.Decapsulate(make([]byte, 32)); err == nil {
		t.Fatal("Decapsulate() before GenerateKeyPair(): expected error, got nil")
	}
}
