package hybrid

import (
	"bytes"
	"testing"
)

// FuzzUnframe exercises unframe's manual length-prefix parsing against
// arbitrary byte slices, the kind of input a real deployment would see
// from a peer, not just a trusted caller. The property under test: it
// must never panic, and on success it must be the exact inverse of
// frame (no trailing data is allowed, so re-framing the parts must
// reproduce the original input).
func FuzzUnframe(f *testing.F) {
	f.Add(frame([]byte("a"), []byte("b")))
	f.Add(frame(nil, nil))
	f.Add(frame([]byte("classical-pubkey"), []byte("pq-pubkey-but-much-longer-than-the-classical-one")))
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add(append(frame([]byte("a"), []byte("b")), 0x00))

	f.Fuzz(func(t *testing.T, data []byte) {
		parts, err := unframe(data)
		if err != nil {
			return
		}
		if got := frame(parts[0], parts[1]); !bytes.Equal(got, data) {
			t.Fatalf("frame(unframe(data)) = %x, want %x", got, data)
		}
	})
}
