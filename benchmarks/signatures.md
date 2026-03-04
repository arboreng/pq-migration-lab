# Signature Benchmarks

Timings for the two registered signature schemes (`internal/sig/classical`,
`internal/sig/pq`), captured with Go's standard benchmarking tooling.
These quantify the relative cost of classical vs. post-quantum signing,
not absolute performance claims; results vary by hardware and will differ
on other machines.

## Reproduce

```sh
docker run --rm pq-migration-lab go test -bench=. -benchmem ./internal/sig/...
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

| Algorithm  | Operation       | ns/op   | B/op  | allocs/op |
| ---------- | --------------- | ------- | ----- | --------- |
| Ed25519    | GenerateKeyPair | 15,870  | 152   | 4         |
| Ed25519    | Sign            | 19,952  | 64    | 1         |
| Ed25519    | Verify          | 43,178  | 0     | 0         |
| ML-DSA-65  | GenerateKeyPair | 108,028 | 6,281 | 6         |
| ML-DSA-65  | Sign            | 426,175 | 3,464 | 2         |
| ML-DSA-65  | Verify          | 96,690  | 0     | 0         |

## Observations

- **Signing is where ML-DSA-65's cost really shows**: ~21x slower than
  Ed25519 (426,175 ns vs. 19,952 ns). This is the clearest "PQ costs more"
  result across either benchmark suite in this repo, unlike the KEM
  benchmarks, where ML-KEM-768 was often faster than X25519 due to
  implementation maturity, ML-DSA-65 signing is substantially more
  expensive by any measure here.
- **Verify is much closer** (96,690 ns vs. 43,178 ns, ~2x): the
  asymmetry between sign and verify cost is a known property of lattice
  signature schemes and is worth factoring into migration planning:
  systems that sign rarely but verify often (e.g. TLS certificates,
  package signing) absorb PQ migration cost more easily than systems that
  sign on a hot path.
- **Zero allocations for both `Verify` implementations**: neither
  `crypto/ed25519.Verify` nor liboqs's `OQS_SIG_verify` (via
  `internal/sig/pq`) allocates for the operation itself, only for setup
  (which happens once per session, outside the timed loop in these
  benchmarks).
- Certificate migration (`pqlab demo cert-migration`) only *issues*
  certificates (an infrequent, one-time-per-cert operation), so
  ML-DSA-65's higher signing cost there is a non-issue in practice; where
  it would matter is a CA signing at high volume, or a leaf signing
  per-request rather than per-session.
