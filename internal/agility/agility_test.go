package agility

import (
	"fmt"
	"sync"
	"testing"
)

type fakeAlgorithm struct {
	name   string
	family Family
}

func (f fakeAlgorithm) Name() string   { return f.name }
func (f fakeAlgorithm) Family() Family { return f.family }

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	algo := fakeAlgorithm{name: "Kyber768", family: FamilyKEM}

	if err := r.Register(algo); err != nil {
		t.Fatalf("Register() returned unexpected error: %v", err)
	}

	got, ok := r.Lookup("Kyber768")
	if !ok {
		t.Fatal("Lookup() did not find registered algorithm")
	}
	if got.Name() != algo.Name() || got.Family() != algo.Family() {
		t.Fatalf("Lookup() = %+v, want %+v", got, algo)
	}
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := NewRegistry()
	algo := fakeAlgorithm{name: "X25519", family: FamilyKEM}

	if err := r.Register(algo); err != nil {
		t.Fatalf("first Register() returned unexpected error: %v", err)
	}
	if err := r.Register(algo); err == nil {
		t.Fatal("second Register() with duplicate name: expected error, got nil")
	}
}

func TestRegistryLookupMissing(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Lookup("does-not-exist"); ok {
		t.Fatal("Lookup() found an algorithm that was never registered")
	}
}

func TestRegistryZeroValue(t *testing.T) {
	var r Registry // no NewRegistry() call
	algo := fakeAlgorithm{name: "ML-KEM-768", family: FamilyKEM}

	if err := r.Register(algo); err != nil {
		t.Fatalf("Register() on zero-value Registry returned unexpected error: %v", err)
	}
	if _, ok := r.Lookup("ML-KEM-768"); !ok {
		t.Fatal("Lookup() on zero-value Registry did not find registered algorithm")
	}
}

func TestRegistryRegisterNil(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("Register(nil): expected error, got nil")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = r.Register(fakeAlgorithm{name: fmt.Sprintf("algo-%d", i), family: FamilyKEM})
		}(i)
		go func() {
			defer wg.Done()
			r.Lookup("algo-0")
		}()
	}
	wg.Wait()
}
