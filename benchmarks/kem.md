# KEM Benchmarks

Timings for the three registered KEMs (`internal/kem/classical`,
`internal/kem/pq`, `internal/kem/hybrid`), captured with Go's standard
benchmarking tooling. These quantify the relative cost of classical vs.
post-quantum vs. hybrid key exchange, not absolute performance claims;
results vary by hardware and will differ on other machines.

## Reproduce

```sh
docker run --rm pq-migration-lab go test -bench=. -benchmem ./internal/kem/...
```

## Environment

| Field           | Value                                      |
| ---------------- | ------------------------------------------ |
| CPU               | Apple M1 Pro                               |
| OS/arch           | `linux/arm64` (Docker dev environment)     |
| Go                | 1.25.12                                    |
| liboqs            | 0.15.0                                     |
| oqs-provider      | 0.11.0                                     |
| OpenSSL           | 3.0.20                                     |

`liboqs`/`oqs-provider` versions are pinned in `docker/Dockerfile`
(`LIBOQS_VERSION`, `OQSPROVIDER_VERSION` build args); rebuilding the image
gets the same versions regardless of host hardware.

## Results

| Algorithm                   | Operation       | ns/op   | B/op  | allocs/op |
| ---------------------------- | --------------- | ------- | ----- | --------- |
| X25519                       | GenerateKeyPair | 37,157  | 376   | 7         |
| X25519                       | Encapsulate     | 75,746  | 496   | 9         |
| X25519                       | Decapsulate     | 36,930  | 128   | 3         |
| ML-KEM-768                   | GenerateKeyPair | 17,542  | 4,112 | 6         |
| ML-KEM-768                   | Encapsulate     | 17,849  | 1,184 | 2         |
| ML-KEM-768                   | Decapsulate     | 20,566  | 32    | 1         |
| Hybrid(X25519+ML-KEM-768)     | GenerateKeyPair | 55,614  | 5,856 | 17        |
| Hybrid(X25519+ML-KEM-768)     | Encapsulate     | 95,339  | 5,152 | 34        |
| Hybrid(X25519+ML-KEM-768)     | Decapsulate     | 59,952  | 2,417 | 24        |

## Observations

- **The hybrid KEM costs roughly the sum of its parts**: unsurprising,
  since `internal/kem/hybrid` just runs both component KEMs and combines
  their outputs (see `docs/architecture.md`). The interesting number
  isn't the hybrid's absolute cost, it's that it's cheap enough to make
  "run both, just in case" a practical default during a migration window
  rather than a meaningful performance trade-off.
- **ML-KEM-768 is not the slow one here**: its `GenerateKeyPair` and
  `Encapsulate` are actually faster than X25519's in this run. That's a
  reflection of implementation maturity, not algorithmic hardness: liboqs
  ships optimized native (C) implementations of ML-KEM, while Go's
  `crypto/ecdh` X25519 is a portable Go implementation. `Encapsulate`
  being ~2x `GenerateKeyPair` for X25519 makes sense structurally: this
  KEM-from-DH construction generates a fresh ephemeral keypair *and* runs
  ECDH on every `Encapsulate` call (see `internal/kem/classical/x25519.go`).
  Don't read these numbers as "ECDH is inherently slower than lattice
  crypto"; they're implementation-specific.
- **Memory allocation profile differs by design**: ML-KEM-768's larger
  key/ciphertext sizes show up directly in `B/op` (4,112 B to generate a
  keypair vs. X25519's 376 B), the visible cost of post-quantum security
  margins.
