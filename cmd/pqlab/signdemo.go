package main

import (
	"fmt"

	"github.com/arboreng/pq-migration-lab/internal/agility"
)

// signDemoMessage is the fixed message signed/verified by runSignDemo.
var signDemoMessage = []byte("pq-migration-lab signature demo")

// runSignDemo looks up name in the registry and runs a full sign/verify
// cycle, printing whether the signature validates.
func runSignDemo(name string) error {
	algo, ok := buildRegistry().Lookup(name)
	if !ok {
		return fmt.Errorf("unknown algorithm %q", name)
	}
	factory, ok := algo.(agility.SignatureFactory)
	if !ok {
		return fmt.Errorf("algorithm %q is not a signature scheme", name)
	}

	session, err := factory.New()
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	defer func() { _ = session.Close() }()

	publicKey, err := session.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	signature, err := session.Sign(signDemoMessage)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	valid, err := session.Verify(signDemoMessage, signature, publicKey)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	fmt.Printf("%s: signature valid = %v\n", name, valid)
	if !valid {
		return fmt.Errorf("signature failed to verify for %q", name)
	}
	return nil
}
