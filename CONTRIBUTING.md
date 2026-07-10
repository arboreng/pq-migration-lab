# Contributing

Thanks for your interest in pq-migration-lab.

## Development

The module cgo-depends on liboqs (`internal/kem/mlkem768` and `internal/sig/mldsa65`,
via `github.com/open-quantum-safe/liboqs-go`), so `go build`/`go vet`/
`go test`/`golangci-lint run` all need liboqs's headers/libs discoverable
via `pkg-config`: see `docker/Dockerfile`'s `oqs-builder` and `devenv`
stages for exactly how that's wired up (a generated `liboqs-go.pc` plus
`PKG_CONFIG_PATH`).

Easiest path: use the containerized dev environment.

```sh
docker build -f docker/Dockerfile -t pq-migration-lab .   # runs vet, lint, test, build
docker compose run pqlab demo X25519
```

To build/test natively (Go 1.25+ required), install liboqs locally
following the `oqs-builder` stage's steps, then point `PKG_CONFIG_PATH` at
a `liboqs-go.pc` like the one generated in `devenv`.

Fuzz targets (e.g. `FuzzUnframe` in `internal/kem/hybrid`) only run their
seed corpus under plain `go test`, which is what CI does. To actually
fuzz, run it directly with a time budget, e.g.:

```sh
docker run --rm -v "$(pwd)":/app -w /app pq-migration-lab \
  go test -fuzz=FuzzUnframe -fuzztime=30s ./internal/kem/hybrid/
```

## Pull Requests

- Keep PRs scoped to a single change.
- Add or update tests for any behavior change.
- Make sure `docker build -f docker/Dockerfile .` succeeds before opening
  a PR: it runs `go vet`, `golangci-lint run`, and `go test -race ./...`,
  the same checks CI runs.

## Reporting Issues

Open a GitHub issue describing the problem or proposal. For security
concerns, please do not open a public issue. See
[`SECURITY.md`](SECURITY.md) instead.
