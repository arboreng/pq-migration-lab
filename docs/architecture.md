# Architecture

This document describes the design goals for pq-migration-lab and how
they're realized: the core algorithm-agility layer, plus four features
built on top of it: the certificate migration and CA rotation demos
(both built on signature agility), the TLS interoperability demo (built
on the hybrid-TLS work), and the benchmark dashboard (built on the
benchmark suite itself). See [`benchmarks/`](../benchmarks) for
performance results referenced below.

## Core Components

- **`cmd/pqlab`**: the CLI entrypoint. `pqlab demo <algorithm-name>` runs
  a full KEM handshake (generate keypair → encapsulate → decapsulate)
  against a registered algorithm and reports whether the shared secrets
  match. `pqlab demo hybrid-tls` (`cmd/pqlab/hybridtls.go`) runs a real
  hybrid TLS 1.3 handshake instead of a library-level KEM composition.
  `pqlab demo sign <algorithm-name>` (`cmd/pqlab/signdemo.go`) runs a
  sign/verify cycle against a registered signature algorithm.
  `pqlab demo cert-migration` (`cmd/pqlab/certmigration.go`) issues
  classical and post-quantum leaf certificates under one classical CA.
  `pqlab demo ca-rotation` (`cmd/pqlab/carotation.go`) goes further and
  rotates the CA itself, from classical to post-quantum, via a
  cross-signed transitional certificate. Broader PKI evolution
  (revocation across a migration, multi-level intermediate hierarchies,
  etc.) remains future work. `pqlab demo interop-tls`
  (`cmd/pqlab/interoptls.go`) proves the hybrid TLS 1.3 group from
  hybrid-tls interoperates with a second, independent implementation
  (Go's own `crypto/tls`), not just with another copy of the same
  OpenSSL+oqs-provider build.
- **`cmd/benchdash`**: a separate binary (not a `pqlab` subcommand,
  since it's a repo dev-tool rather than a migration demo) that runs
  `go test -bench=. -benchmem` against `internal/kem/...` and
  `internal/sig/...`, parses the output, and renders it as a static HTML
  dashboard (`benchmarks/dashboard.html`): grouped bar charts per metric
  plus a table view, replacing what would otherwise be hand-transcribed
  markdown tables.
- **`internal/agility`**: the algorithm-agility extension point:
  `Algorithm`/`Registry` (bookkeeping), `KEMFactory`/`KEMSession` (the
  stateful KEM handshake contract), and `SignatureFactory`/
  `SignatureSession` (the signature contract). Concrete algorithms
  implement and register against these interfaces; nothing else in the
  codebase depends on a specific crypto library directly.
- **`internal/kem/x25519`**: `X25519`, via stdlib `crypto/ecdh`.
- **`internal/kem/mlkem768`**: `ML-KEM-768`, via liboqs (cgo bindings from
  `github.com/open-quantum-safe/liboqs-go`).
- **`internal/kem/hybrid`**: composes any two `KEMFactory`s (by default,
  the two above) into one hybrid KEM.
- **`internal/sig/ed25519`**: `Ed25519`, via stdlib `crypto/ed25519`.
- **`internal/sig/mldsa65`**: `ML-DSA-65`, via liboqs (same cgo bindings as
  `internal/kem/mlkem768`).

## Algorithm Agility as a First-Class Design Goal

Production PQ migrations need to swap algorithms (classical, post-quantum,
or hybrid) without rewriting the code that consumes them. `internal/agility`
defines that seam with two parallel interface pairs, one per algorithm
family:

- `KEMFactory`/`SignatureFactory` are named, registrable schemes
  (`Name()`, `Family()`, and `New()` to start a session). `Registry`
  looks these up by name at runtime (regardless of family, since both
  factory interfaces embed `Algorithm`), so the algorithm in use can come
  from configuration instead of being hard-coded. Its zero value
  (`var r agility.Registry`) is ready to use, and `Register`/`Lookup` are
  safe to call concurrently.
- `KEMSession` is one stateful handshake: `GenerateKeyPair`, then either
  `Encapsulate` (responder) or `Decapsulate` (initiator), then `Close`.
  Each `New()` call gets independent key material, so concurrent
  handshakes don't share state: this is what let `internal/kem/hybrid`
  compose two arbitrary component KEMs generically, without knowing
  their concrete types.
- `SignatureSession` is one signature scheme instance: a signer calls
  `GenerateKeyPair` then `Sign`; a verifier only ever needs `Verify` (with
  the signer's public key passed in directly) and doesn't need its own
  keypair at all.

`cmd/pqlab`'s `buildRegistry()` is the one place that wires concrete
algorithms into the registry: both KEM and signature factories share it,
since `Registry` is generic over `Algorithm`. Everything else (the demo
commands, the hybrid-TLS example) only depends on the `agility`
interfaces or, for TLS, on `oqs-provider`'s group names directly (see
below: TLS groups aren't routed through `internal/agility` at all).

Every concrete factory/session type (`x25519Factory`, `mlkem768Session`,
the hybrid `factory`/`session`, `ed25519Factory`, `mldsa65Session`, etc.)
carries a `var _ agility.KEMFactory = ...` (or `SignatureFactory`/
`*Session`) assertion next to its declaration. Each constructor already
declares its return type as the interface (e.g. `func NewX25519()
agility.KEMFactory`), which forces the same check at the call site: the
assertions are there for readers, not the compiler: they document intent
directly next to the type instead of requiring a trip to the
constructor.

## Extension Points

Certificate migration (`cmd/pqlab/certmigration.go`) builds on signature
agility (`internal/sig/ed25519`, `internal/sig/mldsa65`), the same way
the hybrid-TLS demo builds on KEM agility. CA rotation
(`cmd/pqlab/carotation.go`) builds on cert-migration in turn, reusing its
`issueLeaf` helper. Broader PKI evolution beyond that (revocation across
a migration, multi-level intermediate hierarchies) remains future work.

Transport bindings are handled differently: TLS 1.3's hybrid key exchange
is negotiated by `oqs-provider` (an OpenSSL 3 provider: see
`docker/Dockerfile`'s `oqs-builder` stage) using its own group names (e.g.
`X25519MLKEM768`), not by `internal/kem/hybrid` directly. `internal/kem`
isn't wire-compatible with any TLS implementation: it's a
library-level composition to demonstrate algorithm agility, not a TLS
group. `cmd/pqlab/hybridtls.go` shells out to `openssl s_server`/`s_client`
rather than trying to plug `internal/kem/hybrid` into Go's `crypto/tls`,
since Go's stdlib TLS stack doesn't expose a way to register a custom
hybrid key-exchange group. It doesn't need to for `X25519MLKEM768`
specifically, though: Go's stdlib has implemented that exact group
natively since Go 1.24 (`tls.X25519MLKEM768`, the same IANA codepoint
`0x11ec` oqs-provider uses), which is what makes `cmd/pqlab/interoptls.go`
possible: it drives a real `crypto/tls.Conn` against `oqs-provider` (and
vice versa) instead of shelling out to `openssl` on both ends.

## Data Flow

A KEM handshake, as run by `pqlab demo <name>` (`cmd/pqlab/main.go`):

1. **Initiator**: `session.GenerateKeyPair()` → public key.
2. Public key is sent to the **responder** (in the demo, this is just an
   in-process byte slice; a real transport would send it over the wire).
3. **Responder**: `session.Encapsulate(publicKey)` → `(ciphertext,
   sharedSecret)`.
4. Ciphertext is sent back to the **initiator**.
5. **Initiator**: `session.Decapsulate(ciphertext)` → `sharedSecret`.
6. Both sides now hold the same `sharedSecret` (compared with
   `crypto/subtle.ConstantTimeCompare` in the demo).

For the hybrid KEM (`internal/kem/hybrid`), steps 1–5 happen once per
component algorithm internally: public keys and ciphertexts are
concatenated with a 4-byte length prefix per component (so the wire
format is self-describing, not dependent on hardcoded algorithm sizes),
and the two component shared secrets are combined via HKDF-SHA384 into
the single secret returned to the caller. The framing parser (`unframe`)
does manual offset arithmetic over a byte slice that, in a real
deployment, would come from a peer rather than a trusted caller: it has
a Go native fuzz test (`combiner_fuzz_test.go`) checking it never panics
and is the exact inverse of `frame` on any input that parses
successfully.

The hybrid TLS demo (`pqlab demo hybrid-tls`) is a separate flow, at the
protocol layer instead of the library layer:

1. Generate an ephemeral, classical (ECDSA P-256) self-signed certificate
   Only the key-exchange group is post-quantum/hybrid in this demo.
2. Start `openssl s_server -tls1_3 -groups X25519MLKEM768 ...` (loading
   `oqs-provider`) as a subprocess, restricted to exactly one TLS 1.3
   group, no fallback offered.
3. Connect with `openssl s_client -tls1_3 -groups X25519MLKEM768 ...` as
   another subprocess, restricted the same way.
4. Confirm the client reports a completed TLS 1.3 handshake (`New,
   TLSv1.3, ...` followed by `DONE`). TLS 1.3 requires a negotiated group
   for every handshake, and neither side offered anything but
   `X25519MLKEM768`, so a successful handshake is only possible if that
   exact hybrid group was used. `openssl s_client` doesn't reliably
   surface the negotiated group name directly for this provider/OpenSSL
   combination (`SSL_get_peer_tmp_key` returns nothing for it here), so
   this structural proof stands in for grepping a group name out of its
   output.

The TLS interoperability demo (`pqlab demo interop-tls`) exercises the
same `X25519MLKEM768` group as hybrid-tls, but across two independent
implementations instead of openssl talking to itself, in both
directions:

1. A Go-native `tls.Listen` server, `CurvePreferences` restricted to
   `tls.X25519MLKEM768`, against an `openssl s_client` restricted to the
   same group name. Unlike hybrid-tls's structural inference, the Go
   side directly reads back `tls.Conn.ConnectionState().CurveID` after
   the handshake and compares it against `tls.X25519MLKEM768`: direct
   confirmation, not just "no other group was on offer."
2. The reverse: an `openssl s_server` (identical invocation to
   hybrid-tls's) against a Go-native `tls.Dial` client, same
   `CurvePreferences` restriction, same `ConnectionState().CurveID`
   check.

Both directions reuse `generateEphemeralCert` from hybridtls.go for the
server's self-signed certificate, which carries a `127.0.0.1` IP SAN
(added alongside interop-tls) so the Go client in direction 2 can verify
it properly via `x509.CertPool` instead of `InsecureSkipVerify`: Go's
`crypto/x509` has ignored a certificate's `CommonName` for hostname
matching since Go 1.15, unlike `openssl s_client`, which never needed the
SAN in the first place.

A signature cycle, as run by `pqlab demo sign <name>`
(`cmd/pqlab/signdemo.go`):

1. **Signer**: `session.GenerateKeyPair()` → public key.
2. **Signer**: `session.Sign(message)` → signature.
3. Public key and signature are sent to the **verifier** (again, in-process
   byte slices in the demo; a real deployment would carry these over the
   wire or via a certificate).
4. **Verifier**: `session.Verify(message, signature, publicKey)` → `bool`.
   Unlike the KEM flow, the verifier session never calls
   `GenerateKeyPair`: verification only needs the public key, not a
   keypair of its own.

The certificate migration demo (`pqlab demo cert-migration`) is, like
hybrid-tls, entirely `openssl`-subprocess-orchestrated rather than using
`internal/sig` directly: Go's stdlib `x509.CreateCertificate` and
`x509.MarshalPKIXPublicKey` only recognize RSA/ECDSA/Ed25519 public keys,
so they can't produce (or even represent) a certificate carrying an
ML-DSA-65 subject public key. The flow:

1. Issue a self-signed classical (Ed25519) CA: `openssl req -x509
   -newkey ed25519 ...`.
2. Issue a classical leaf (Ed25519 key, `-newkey ed25519`), signed by
   that CA via `openssl req` + `openssl x509 -req -CA ...`.
3. Issue a post-quantum leaf (ML-DSA-65 key, `-newkey mldsa65`, with
   `-provider default -provider oqsprovider`), signed by the *same*
   classical CA, no CA migration required.
4. `openssl verify -CAfile <ca>` both leaves. Both succeed: the CA's own
   signing algorithm (Ed25519) is independent of each leaf's key
   algorithm, which is exactly the incremental-migration pattern real
   PKI operators rely on: issue PQ leaf certificates before the CA
   itself ever needs to change.

The CA rotation demo (`pqlab demo ca-rotation`) goes one step further and
migrates the CA's own signing algorithm, again entirely
`openssl`-subprocess-orchestrated. The trick is a *cross-certificate*: a
certificate carrying the new CA's subject and public key, but signed by
the old CA, so certificates issued under the new CA chain back to the
old, already-trusted root during the transition, without every relying
party needing to add the new root as a trust anchor on day one. The flow:

1. Issue a self-signed classical (Ed25519) CA (`old-ca`), then a leaf
   under it (`legacy-leaf`), representing certificates already issued
   before the rotation.
2. Issue a self-signed post-quantum (ML-DSA-65) CA (`new-ca`), with
   `basicConstraints=CA:TRUE` and `keyUsage=keyCertSign,cRLSign` set via
   `-addext` (`x509 -req`'s defaults don't mark a certificate as a CA).
3. Cross-sign: create a CSR for `new-ca`'s existing key/subject requesting
   the same CA extensions, then issue it under `old-ca` with
   `-copy_extensions copy` (`x509 -req` has no `-addext` of its own: it
   only carries over extensions the CSR itself requested) to produce
   `cross.crt`: a certificate the old CA vouches for, carrying the new
   CA's identity, key, and CA extensions.
4. Issue a leaf under `new-ca` (`new-leaf`), representing certificates
   issued after the rotation.
5. Four `openssl verify` checks confirm the rotation is safe, including
   the negative case: `legacy-leaf` still verifies against `old-ca`
   (rotation doesn't break existing certificates); `new-leaf` *fails* to
   verify against `old-ca` alone (the old CA never signed anything from
   the new CA, so an old client with no cross-cert correctly rejects it);
   `new-leaf` verifies directly against `new-ca` (relying parties who've
   already adopted the new root trust it immediately); and `new-leaf`
   verifies against a bundle of `cross.crt` + `old-ca` supplied together
   as `-CAfile` (representing a relying party who *hasn't* adopted the
   new root yet: it still validates `new-leaf`, via the cross-signed
   bridge, the fix for the negative case above). This last check needs
   the cross-cert bundled into `-CAfile` rather than passed via
   `-untrusted`: with this openssl/oqs-provider combination, `-untrusted`
   hits a decode error fetching the intermediate's ML-DSA-65 public key
   mid-chain-build, while `-CAfile` doesn't.

## Performance

[`benchmarks/kem.md`](../benchmarks/kem.md) and
[`benchmarks/signatures.md`](../benchmarks/signatures.md) benchmark every
algorithm registered above, with narrative analysis;
[`benchmarks/dashboard.html`](../benchmarks/dashboard.html) covers the
same data as generated bar charts plus a table view. The least intuitive
result: ML-KEM-768's `GenerateKeyPair`/`Encapsulate` are actually *faster*
than X25519's in these benchmarks: an artifact of liboqs's optimized
native implementation versus Go's portable `crypto/ecdh`, not a claim
that lattice cryptography is inherently cheaper. ML-DSA-65 signing, on
the other hand, is genuinely ~19x slower than Ed25519: the clearest
"post-quantum costs more" result across either benchmark suite.

`cmd/benchdash` (`cmd/benchdash/parse.go`, `render.go`, `main.go`) runs
`go test -run=^$ -bench=. -benchmem` itself against `./internal/kem/...`
and `./internal/sig/...`, parses each `BenchmarkXxxYyy-N ... ns/op ...
B/op ... allocs/op` result line by matching this repo's fixed
`Benchmark<Algorithm><Operation>` naming convention (`parseBenchLine`),
and renders one grouped bar chart per (suite, metric) pair, never a
dual-axis chart mixing time and memory. Categorical color is assigned by
a fixed slot per algorithm's role (slot 1/blue = classical, slot 2/aqua =
post-quantum, slot 3/yellow = hybrid), so color means the same thing in
every chart rather than being reassigned per suite. Every bar carries a
visible value label (small dataset, so labeling all of them is legible)
and a hover/focus tooltip; a collapsible table view underneath keeps
every value reachable without relying on the chart at all. Unlike
`kem.md`/`signatures.md` (a hand-captured snapshot with narrative
analysis, regenerated by a human when it's worth re-benchmarking),
`benchmarks/dashboard.html` is meant to be regenerated by running
`cmd/benchdash` again: CI only smoke-tests that it runs successfully,
since the actual numbers are hardware-dependent and expected to vary
between runs.
