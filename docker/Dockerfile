# syntax=docker/dockerfile:1

# Declared before the first FROM so it's visible to devenv's FROM below
# (build ARGs used in a FROM must be declared before the file's first FROM).
ARG GO_VERSION=1.25

# Stage 1: build liboqs and the oqs-provider OpenSSL 3 provider from source.
# Pinned versions keep the dev/CI environment reproducible.
FROM debian:bookworm-slim AS oqs-builder

ARG LIBOQS_VERSION=0.15.0
ARG OQSPROVIDER_VERSION=0.11.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    ca-certificates \
    libssl-dev \
    openssl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build -GNinja \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_USE_OPENSSL=OFF && \
    cmake --build liboqs/build --parallel && \
    cmake --install liboqs/build

# oqs-provider's CMake install ignores -DCMAKE_INSTALL_PREFIX for the
# provider .so itself: it always installs oqsprovider.so to the local
# OpenSSL's own MODULESDIR (e.g. /usr/lib/<triplet>/ossl-modules), outside
# /opt/oqs. Relocate it under /opt/oqs so it's included in the COPY into
# later stages instead of being silently left behind in this stage's
# filesystem.
RUN git clone --depth 1 --branch ${OQSPROVIDER_VERSION} https://github.com/open-quantum-safe/oqs-provider.git && \
    cmake -S oqs-provider -B oqs-provider/build -GNinja \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs && \
    cmake --build oqs-provider/build --parallel && \
    cmake --install oqs-provider/build && \
    modules_dir="$(openssl version -m | sed -E 's/MODULESDIR: "(.*)"/\1/')" && \
    mkdir -p /opt/oqs/lib/ossl-modules && \
    cp "${modules_dir}/oqsprovider.so" /opt/oqs/lib/ossl-modules/

# Stage 2: Go environment with liboqs and oqs-provider wired up for cgo
# (via pkg-config) and OpenSSL provider loading. Reusable on its own for
# local development (e.g. `go mod tidy`) without re-running go build/test.
FROM golang:${GO_VERSION}-bookworm AS devenv

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=oqs-builder /opt/oqs /opt/oqs

# liboqs-go's cgo directive resolves its build flags via `pkg-config
# liboqs-go` (not plain CGO_CFLAGS/CGO_LDFLAGS), so it needs its own .pc
# file pointing at where liboqs was installed above.
RUN mkdir -p /opt/oqs/pkgconfig && cat <<'EOF' > /opt/oqs/pkgconfig/liboqs-go.pc
LIBOQS_INCLUDE_DIR=/opt/oqs/include
LIBOQS_LIB_DIR=/opt/oqs/lib

Name: liboqs-go
Description: Go bindings for liboqs, a C library for quantum resistant cryptography
Version: 0.15.0
Cflags: -I${LIBOQS_INCLUDE_DIR}
Libs: -L${LIBOQS_LIB_DIR} -loqs
EOF

ENV PKG_CONFIG_PATH="/opt/oqs/pkgconfig"
ENV CGO_CFLAGS="-I/opt/oqs/include"
ENV CGO_LDFLAGS="-L/opt/oqs/lib"
ENV LD_LIBRARY_PATH="/opt/oqs/lib"
ENV OPENSSL_MODULES="/opt/oqs/lib/ossl-modules"

RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

# Stage 3: vet, lint, test, and build pqlab using the dev environment
# above. This is what CI runs so liboqs-dependent packages are always
# checked where liboqs is actually available.
FROM devenv AS build

WORKDIR /app
COPY . .

RUN go vet ./... && golangci-lint run && go test -race ./... && go build -o /out/pqlab ./cmd/pqlab

CMD ["/out/pqlab"]
