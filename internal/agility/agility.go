// Package agility defines the extension points that let pq-migration-lab
// swap cryptographic algorithms without changing calling code: the
// "algorithm agility" design goal.
//
// This package holds the interface definitions and a registry. Concrete
// algorithm implementations (classical and post-quantum) live in
// internal/kem and internal/sig.
package agility

import (
	"errors"
	"fmt"
	"sync"
)

// Family identifies the cryptographic category an Algorithm belongs to.
type Family string

const (
	FamilyKEM       Family = "kem"
	FamilySignature Family = "signature"
)

// Algorithm is implemented by any concrete cryptographic scheme
// (classical, post-quantum, or hybrid) that the lab can plug in.
type Algorithm interface {
	// Name returns the algorithm's identifier, e.g. "Kyber768" or "X25519".
	Name() string
	// Family reports which cryptographic category the algorithm belongs to.
	Family() Family
}

// Registry looks up registered Algorithms by name, so callers can select
// an algorithm at runtime (e.g. from config) instead of at compile time.
// The zero value is ready to use; Register and Lookup are safe to call
// concurrently from multiple goroutines.
type Registry struct {
	mu         sync.RWMutex
	algorithms map[string]Algorithm
}

// NewRegistry returns an empty Registry ready for use. Equivalent to the
// zero value (var r Registry); provided for discoverability.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds algo to the registry under its own Name(). It returns an
// error if algo is nil or an algorithm with the same name is already
// registered.
func (r *Registry) Register(algo Algorithm) error {
	if algo == nil {
		return errors.New("agility: cannot register a nil algorithm")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.algorithms[algo.Name()]; exists {
		return fmt.Errorf("agility: algorithm %q already registered", algo.Name())
	}
	if r.algorithms == nil {
		r.algorithms = make(map[string]Algorithm)
	}
	r.algorithms[algo.Name()] = algo
	return nil
}

// Lookup returns the Algorithm registered under name, if any.
func (r *Registry) Lookup(name string) (Algorithm, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	algo, ok := r.algorithms[name]
	return algo, ok
}
