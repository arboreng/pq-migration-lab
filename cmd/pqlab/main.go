// Command pqlab is the entrypoint for the pq-migration-lab tooling.
//
// It demonstrates the algorithm-agility registry (internal/agility) wired
// up with real KEM implementations: a classical KEM (X25519), a
// post-quantum KEM (ML-KEM-768, via liboqs), and a hybrid combiner of the
// two, plus a real hybrid TLS 1.3 handshake (demo "hybrid-tls") using
// the same X25519+ML-KEM-768 pairing via oqs-provider, and signature
// algorithm agility (demo sign <name>): classical Ed25519 and
// post-quantum ML-DSA-65. demo "cert-migration" issues classical and
// post-quantum leaf certificates under one classical CA, showing that
// the CA doesn't need to migrate first. demo "ca-rotation" goes a step
// further and rotates the CA itself from classical to post-quantum via a
// cross-signed transitional certificate. demo "interop-tls" proves the
// hybrid TLS 1.3 group from hybrid-tls interoperates between Go's native
// crypto/tls and OpenSSL+oqs-provider, not just openssl with itself.
package main

import (
	"crypto/subtle"
	"fmt"
	"os"

	"github.com/arboreng/pq-migration-lab/internal/agility"
	kemclassical "github.com/arboreng/pq-migration-lab/internal/kem/classical"
	"github.com/arboreng/pq-migration-lab/internal/kem/hybrid"
	kempq "github.com/arboreng/pq-migration-lab/internal/kem/pq"
	sigclassical "github.com/arboreng/pq-migration-lab/internal/sig/classical"
	sigpq "github.com/arboreng/pq-migration-lab/internal/sig/pq"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage:
  pqlab demo <kem-name>        run a KEM handshake (X25519, ML-KEM-768, "Hybrid(X25519+ML-KEM-768)")
  pqlab demo sign <sig-name>   run a sign/verify cycle (Ed25519, ML-DSA-65)
  pqlab demo hybrid-tls        hybrid TLS 1.3 handshake over real openssl s_server/s_client
  pqlab demo interop-tls       the same hybrid TLS group, Go crypto/tls <-> openssl+oqs-provider
  pqlab demo cert-migration    issue classical + post-quantum leaf certs under one classical CA
  pqlab demo ca-rotation       rotate a CA from classical to post-quantum via a cross-signed cert`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("pqlab %s\n", version)
		fmt.Println(usage)
		return
	}

	var err error
	switch {
	case os.Args[1] == "demo" && len(os.Args) == 3:
		err = runDemo(os.Args[2])
	case os.Args[1] == "demo" && len(os.Args) == 4 && os.Args[2] == "sign":
		err = runSignDemo(os.Args[3])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// buildRegistry registers every KEM and signature algorithm this build
// knows about, in one shared registry.
func buildRegistry() *agility.Registry {
	r := agility.NewRegistry()
	x25519 := kemclassical.NewX25519()
	mlkem768 := kempq.NewMLKEM768()
	hybridKEM := hybrid.NewHybrid(x25519, mlkem768)
	ed25519 := sigclassical.NewEd25519()
	mldsa65 := sigpq.NewMLDSA65()

	algorithms := []agility.Algorithm{x25519, mlkem768, hybridKEM, ed25519, mldsa65}
	for _, a := range algorithms {
		if err := r.Register(a); err != nil {
			// Names are fixed at compile time, so a collision here is a bug,
			// not a runtime condition callers need to handle.
			panic(err)
		}
	}
	return r
}

// runDemo looks up name in the registry and runs a full KEM handshake
// (generate keypair -> encapsulate -> decapsulate), printing whether the
// initiator's and responder's shared secrets match.
func runDemo(name string) error {
	if name == "hybrid-tls" {
		return runHybridTLSDemo()
	}
	if name == "cert-migration" {
		return runCertMigrationDemo()
	}
	if name == "ca-rotation" {
		return runCARotationDemo()
	}
	if name == "interop-tls" {
		return runInteropTLSDemo()
	}

	algo, ok := buildRegistry().Lookup(name)
	if !ok {
		return fmt.Errorf("unknown algorithm %q", name)
	}
	factory, ok := algo.(agility.KEMFactory)
	if !ok {
		return fmt.Errorf("algorithm %q is not a KEM", name)
	}

	initiator, err := factory.New()
	if err != nil {
		return fmt.Errorf("initiator session: %w", err)
	}
	defer func() { _ = initiator.Close() }()

	responder, err := factory.New()
	if err != nil {
		return fmt.Errorf("responder session: %w", err)
	}
	defer func() { _ = responder.Close() }()

	publicKey, err := initiator.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	ciphertext, responderSecret, err := responder.Encapsulate(publicKey)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}

	initiatorSecret, err := initiator.Decapsulate(ciphertext)
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}

	match := subtle.ConstantTimeCompare(initiatorSecret, responderSecret) == 1
	fmt.Printf("%s: shared secrets match = %v (%d bytes)\n", name, match, len(initiatorSecret))
	if !match {
		return fmt.Errorf("shared secret mismatch for %q", name)
	}
	return nil
}
