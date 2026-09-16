# pq-migration-lab

[![CI](https://github.com/arboreng/pq-migration-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/arboreng/pq-migration-lab/actions/workflows/ci.yml)

A hands-on lab for post-quantum (PQ) cryptography **migration**:
production-quality engineering, operational migration patterns, and
algorithm agility, rather than standalone cryptographic implementations.

## Motivation

Standards for post-quantum cryptography exist, and reference
implementations of the algorithms themselves exist, but there's a gap in
between: what actually breaks when a real system migrates? A CA doesn't
have to migrate its own signing algorithm before it can issue
post-quantum leaf certificates. A TLS handshake needs a hybrid group
negotiated before either side can safely drop the classical one. None of
it works unless the calling code can swap algorithms without a rewrite,
the algorithm agility this repo is built around. This repo focuses on
that gap: hybrid deployments, certificate migration, CA rotation,
interoperability, benchmarking, and rollout strategies.

## Scope

This is a lab. It runs migration mechanics end to end in a pinned
container so the failure modes are reproducible. What it establishes is
where a post-quantum cutover actually breaks, and the answer is mostly
tooling, not cryptography.

It does not do the following, and none of it was left out by accident:

- **No network measurement.** Nothing here contacts a host you do not
  run. Every client connection in the demos targets `127.0.0.1`, against
  a server the same command started moments earlier. Note that the two
  `openssl s_server` subprocesses bind all interfaces (ports 14433 and
  14435) for the few seconds they are alive, which is one reason the
  documented path runs everything inside the container. Outbound access
  is confined to the Docker build: base images, Debian packages, Go
  modules, and the pinned liboqs and oqs-provider sources.
- **No inventory.** This does not discover cryptographic dependencies
  in a running estate.
- **No post-quantum authentication in TLS.** The demo servers present
  ECDSA P-256 certificates. Post-quantum signatures appear only at the
  PKI layer, in certificate issuance. Go 1.27 added ML-DSA signature
  schemes to `crypto/tls` on 19 August 2026, so this is now reachable in
  the standard library. This lab predates that and does not use it.
- **No standards-track hybrid combiner.** `internal/kem/hybrid`
  combines its two component secrets with HKDF-SHA384 under the
  repo-specific info string `"pq-migration-lab hybrid kem v1"`. It is
  not wire-compatible with any TLS implementation, and it is not the
  group the TLS demos negotiate. The two things named "hybrid" in this
  repo never meet: see [`docs/architecture.md`](docs/architecture.md).
- **No revocation, no multi-level intermediates.** PKI coverage stops
  at CA rotation.
- **Not production cryptography.** This composes Go's standard library,
  liboqs, and oqs-provider. Everything substantive sits under
  `internal/`, which Go enforces as non-importable.

The demos also differ in proof strength, and the
[Examples](#examples) section says which is which. `hybrid-tls` infers
its result structurally. `interop-tls` reads the negotiated group back
directly. `ca-rotation` is the strongest, because one of its four
checks has to fail for the rotation to be safe.

[Architecture Field Note: pq-migration-lab](https://arboreng.com/field-notes/pq-migration-lab)
reviews this repository in more depth, including which of its demos
prove something and which only infer it.

## Quick Start

```sh
git clone https://github.com/arboreng/pq-migration-lab.git
cd pq-migration-lab
docker compose run pqlab demo hybrid-tls
docker compose run pqlab demo cert-migration
docker compose run pqlab demo ca-rotation
docker compose run pqlab demo interop-tls
```

This builds the containerized dev environment (Go + OpenSSL + liboqs +
oqs-provider) and runs each migration demo end to end. See
[Examples](#examples) below for what each one actually proves; raw KEM
and signature demos (the individual algorithms these demos build on)
are there too.

The module cgo-depends on liboqs, so building or testing outside Docker
requires liboqs installed locally (see `docker/Dockerfile`'s `oqs-builder`
stage) with `pkg-config` able to find it. Inside Docker:

```sh
docker build -f docker/Dockerfile -t pq-migration-lab .
```

runs `go vet`, `golangci-lint run`, `go test -race`, and `go build` as
part of the image build.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for core components and
the algorithm-agility design goal.

## Migration Patterns

The classic hybrid-deployment pattern for migrating key exchange: run a
classical and a post-quantum KEM side by side (rather than cutting over
directly), so a break in either algorithm alone doesn't break the
handshake. `internal/kem/hybrid` demonstrates this pattern at the
library level. The `hybrid-tls` example below demonstrates the same
pattern over a real TLS 1.3 handshake, by a separate path that never
touches `internal/kem/hybrid`.

For certificates: a CA doesn't have to migrate its own signing algorithm
before it can start issuing post-quantum leaf certificates: the CA's
signing algorithm and a leaf's key algorithm are independent. The
`cert-migration` example below issues both a classical and a
post-quantum leaf certificate under the *same* classical CA.

Eventually the CA itself has to migrate. The `ca-rotation` example below
rotates a CA from a classical to a post-quantum signing algorithm via a
cross-signed transitional certificate, so relying parties who haven't yet
adopted the new root as a trust anchor still validate certificates issued
under it, the same bridge real CA/root rotations use.

Algorithm agility within one codebase isn't the whole story. A migrated
stack also has to interoperate with whatever your peers are running.
The `interop-tls` example below proves the hybrid group from `hybrid-tls`
works the same way in a second, independent implementation (Go's stdlib
`crypto/tls`), not just between two copies of the same OpenSSL build.

## Examples

```sh
docker compose run pqlab demo hybrid-tls
```

Starts an `openssl s_server` offering *only* the hybrid TLS 1.3 group
`X25519MLKEM768` (via `oqs-provider`), connects to it with `openssl
s_client` restricted to that same single group, and confirms the
handshake completed: since TLS 1.3 requires a negotiated group and no
fallback was offered on either side, a successful handshake is only
possible if the hybrid group was actually used. Proves classical +
post-quantum key exchange works together over a real TLS 1.3 connection,
not just as a standalone library composition.

```sh
docker compose run pqlab demo cert-migration
```

Issues a classical (Ed25519) CA, then a classical (Ed25519) leaf
certificate and a post-quantum (ML-DSA-65, via `oqs-provider`) leaf
certificate, both signed by that same CA. Verifies both leaves against
the CA to prove the CA didn't need to change algorithms to support a
post-quantum leaf.

```sh
docker compose run pqlab demo ca-rotation
```

Issues a classical (Ed25519) CA and a leaf under it, then rotates to a
new post-quantum (ML-DSA-65) CA and cross-signs the new CA's key under
the old one. Confirms four things: the pre-rotation leaf still verifies
against the old CA; a leaf issued after rotation *fails* to verify
against the old CA alone, since the old CA never signed anything from
the new CA; that same leaf verifies directly against the new CA; and
that it *also* verifies against the old CA's trust anchor via the
cross-cert, proving relying parties who haven't yet added the new root
still validate certificates issued under it, and relying parties who
haven't cross-signed at all would reject them.

```sh
docker compose run pqlab demo interop-tls
```

Runs the hybrid TLS 1.3 group `X25519MLKEM768` in both directions between
Go's native `crypto/tls` (which implements the same IANA-assigned
codepoint as `tls.X25519MLKEM768`) and OpenSSL+`oqs-provider`: a Go
server against an `openssl s_client`, and an `openssl s_server` against a
Go client. Confirms two independent implementations of the same
standardized hybrid key exchange actually interoperate. `hybrid-tls`
only proves openssl agrees with itself.

### Raw Algorithm Demos

The migration demos above are built on these lower-level, single-algorithm
demos:

```sh
docker compose run pqlab demo X25519
docker compose run pqlab demo ML-KEM-768
docker compose run pqlab demo "Hybrid(X25519+ML-KEM-768)"
```

Runs a full KEM handshake (generate keypair, encapsulate, decapsulate)
for the named algorithm, reporting whether the two sides' shared secrets
match.

```sh
docker compose run pqlab demo sign Ed25519
docker compose run pqlab demo sign ML-DSA-65
```

Runs a full sign/verify cycle against a classical (`Ed25519`) or
post-quantum (`ML-DSA-65`, via liboqs) signature algorithm, reporting
whether the signature validates.

## Benchmarks

- [`benchmarks/dashboard.html`](benchmarks/dashboard.html): a generated,
  visual dashboard (grouped bar charts + a table view) covering every
  algorithm and metric below in one place. Open it directly in a browser.
- [`benchmarks/kem.md`](benchmarks/kem.md): X25519 vs. ML-KEM-768 vs.
  their hybrid combination, with narrative analysis.
- [`benchmarks/signatures.md`](benchmarks/signatures.md): Ed25519 vs.
  ML-DSA-65, with narrative analysis.

Reproduce the raw numbers with `docker run --rm pq-migration-lab go test
-bench=. -benchmem ./internal/kem/... ./internal/sig/...`, or regenerate
the dashboard directly with `docker run --rm -v "$(pwd):/app"
pq-migration-lab go run ./cmd/benchdash` (writes `benchmarks/dashboard.html`
on the host; pass `-out` for a different path). The volume mount is what
makes the write land on the host instead of the container's throwaway
filesystem. `cmd/benchdash` runs both benchmark suites itself and parses
`go test`'s own output; nothing here is hand-transcribed.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). For security issues, see
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE)
