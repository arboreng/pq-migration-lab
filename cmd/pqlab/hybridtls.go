package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// hybridTLSGroup is the IETF-draft hybrid TLS 1.3 group name for
// X25519+ML-KEM-768, as implemented by oqs-provider. It's the same
// algorithm pairing as internal/kem/hybrid's default registration, but
// exercised here as a real TLS 1.3 key-exchange group rather than a
// standalone KEM composition.
const hybridTLSGroup = "X25519MLKEM768"

// hybridTLSPort is a fixed port for the ephemeral demo server. Each demo
// run happens in its own short-lived process/container, so a fixed port
// is simpler than dynamic allocation and safe in practice.
const hybridTLSPort = 14433

// runHybridTLSDemo starts an openssl s_server offering the hybrid TLS 1.3
// group X25519MLKEM768 (via oqs-provider), connects to it with openssl
// s_client requesting the same group, and confirms from the client's
// output that the hybrid group was actually negotiated.
func runHybridTLSDemo() error {
	certPath, keyPath, cleanup, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("generate ephemeral cert: %w", err)
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := exec.CommandContext(ctx, "openssl", "s_server",
		"-cert", certPath,
		"-key", keyPath,
		"-www",
		"-tls1_3",
		"-groups", hybridTLSGroup,
		"-provider", "default",
		"-provider", "oqsprovider",
		"-accept", strconv.Itoa(hybridTLSPort),
		"-quiet",
	)
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput
	if err := server.Start(); err != nil {
		return fmt.Errorf("start openssl s_server: %w", err)
	}
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	}()

	if err := waitForPort(hybridTLSPort, 2*time.Second); err != nil {
		return fmt.Errorf("s_server never accepted connections: %w\nserver output:\n%s", err, serverOutput.String())
	}

	client := exec.CommandContext(ctx, "openssl", "s_client",
		"-groups", hybridTLSGroup,
		"-provider", "default",
		"-provider", "oqsprovider",
		"-connect", fmt.Sprintf("127.0.0.1:%d", hybridTLSPort),
	)
	client.Stdin = bytes.NewReader(nil) // EOF immediately, so s_client exits after the handshake
	clientOutput, err := client.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl s_client: %w\noutput:\n%s", err, clientOutput)
	}

	// oqs-provider's hybrid group doesn't reliably populate the peer temp
	// key info s_client would otherwise print (SSL_get_peer_tmp_key
	// returns nothing for it under this OpenSSL/provider combination), so
	// we can't just grep for the group name. Instead: both s_server and
	// s_client were restricted to exactly one TLS 1.3 group
	// (hybridTLSGroup) via -groups, with no fallback offered on either
	// side. TLS 1.3 requires a negotiated group for every handshake, so a
	// successful "New, TLSv1.3, ..." handshake summary is only possible
	// if that exact group was used.
	success := bytes.Contains(clientOutput, []byte("New, TLSv1.3,")) && bytes.Contains(clientOutput, []byte("\nDONE"))
	fmt.Printf("hybrid-tls: TLS 1.3 handshake using the sole offered group %s succeeded = %v\n", hybridTLSGroup, success)
	if !success {
		return fmt.Errorf("handshake did not complete cleanly using group %q:\n%s", hybridTLSGroup, clientOutput)
	}
	return nil
}

// waitForPort retries dialing addr until it accepts a connection or
// timeout elapses.
func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return conn.Close()
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

// generateEphemeralCert creates a self-signed ECDSA P-256 certificate and
// key in a temp directory for the demo TLS server. Only the key-exchange
// group is post-quantum/hybrid here; certificate/PKI migration is covered
// separately by the cert-migration and ca-rotation demos, so the
// certificate itself stays classical.
func generateEphemeralCert() (certPath, keyPath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "pqlab-hybrid-tls-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pq-migration-lab hybrid-tls demo"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// An IP SAN, not just the CommonName above, since crypto/tls's
		// client-side verification (used by interoptls.go) has ignored
		// CommonName for hostname matching since Go 1.15; openssl s_client
		// (the only consumer of this cert otherwise) doesn't care either
		// way.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	closeErr := certOut.Close()
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	if closeErr != nil {
		cleanup()
		return "", "", nil, closeErr
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	closeErr = keyOut.Close()
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	if closeErr != nil {
		cleanup()
		return "", "", nil, closeErr
	}

	return certPath, keyPath, cleanup, nil
}
