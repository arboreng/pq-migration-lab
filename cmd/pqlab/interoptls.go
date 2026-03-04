package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// interopTLSGroup is the same standardized hybrid TLS 1.3 group as
// hybridTLSGroup (X25519+ML-KEM-768), spelled the way oqs-provider names
// it. Go's stdlib crypto/tls implements the identical IANA codepoint as
// tls.X25519MLKEM768 (0x11ec), so forcing this exact group on both a
// Go-native and an OpenSSL+oqs-provider peer proves two independent
// implementations of the same IETF-standard hybrid key exchange actually
// interoperate, rather than just that pq-migration-lab's own
// openssl-vs-openssl demo (hybrid-tls) is internally consistent.
const interopTLSGroup = "X25519MLKEM768"

// Fixed ports for the demo's two directions, distinct from hybridTLSPort
// so nothing here collides with the hybrid-tls demo if ever run alongside
// it.
const (
	interopGoServerPort      = 14434
	interopOpenSSLServerPort = 14435
)

// runInteropTLSDemo proves the hybrid TLS 1.3 group X25519MLKEM768
// interoperates between Go's native crypto/tls and OpenSSL+oqs-provider,
// in both directions: a Go server against an openssl client, and an
// openssl server against a Go client. Unlike hybrid-tls (openssl on both
// ends), the Go side here directly reads back the negotiated
// ConnectionState.CurveID instead of relying on the "only one group was
// offered" structural inference: direct proof, not just an absence of
// alternatives.
func runInteropTLSDemo() error {
	certPath, keyPath, cleanup, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("generate ephemeral cert: %w", err)
	}
	defer cleanup()

	if err := runGoServerOpenSSLClient(certPath, keyPath); err != nil {
		return fmt.Errorf("go server / openssl client: %w", err)
	}
	if err := runOpenSSLServerGoClient(certPath, keyPath); err != nil {
		return fmt.Errorf("openssl server / go client: %w", err)
	}
	return nil
}

// runGoServerOpenSSLClient starts a Go-native TLS 1.3 server restricted
// to interopTLSGroup, connects to it with openssl s_client restricted to
// the same group, and confirms both that the client's handshake
// completed and that the Go server's side recorded the expected
// negotiated group.
func runGoServerOpenSSLClient(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load server keypair: %w", err)
	}

	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", interopGoServerPort), &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = ln.Close() }()

	type serverResult struct {
		curve tls.CurveID
		err   error
	}
	done := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- serverResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			done <- serverResult{err: fmt.Errorf("server-side handshake: %w", err)}
			return
		}
		if _, err := tlsConn.Write([]byte("pq-migration-lab interop-tls demo\n")); err != nil {
			done <- serverResult{err: fmt.Errorf("server write: %w", err)}
			return
		}
		done <- serverResult{curve: tlsConn.ConnectionState().CurveID}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, "openssl", "s_client",
		"-groups", interopTLSGroup,
		"-provider", "default",
		"-provider", "oqsprovider",
		"-connect", fmt.Sprintf("127.0.0.1:%d", interopGoServerPort),
	)
	client.Stdin = bytes.NewReader(nil) // EOF immediately, so s_client exits once the server closes the connection
	clientOutput, clientErr := client.CombinedOutput()

	res := <-done
	if res.err != nil {
		return fmt.Errorf("go server: %w\nopenssl s_client output:\n%s", res.err, clientOutput)
	}
	if clientErr != nil {
		return fmt.Errorf("openssl s_client: %w\noutput:\n%s", clientErr, clientOutput)
	}

	success := res.curve == tls.X25519MLKEM768 && bytes.Contains(clientOutput, []byte("New, TLSv1.3,"))
	fmt.Printf("interop-tls: go server + openssl client negotiated %s = %v\n", interopTLSGroup, success)
	if !success {
		return fmt.Errorf("go server recorded curve %d, want %d (X25519MLKEM768); openssl s_client output:\n%s",
			res.curve, tls.X25519MLKEM768, clientOutput)
	}
	return nil
}

// runOpenSSLServerGoClient starts an openssl s_server restricted to
// interopTLSGroup (the same process hybrid-tls uses), connects to it
// with a Go-native TLS client restricted to the same group, and confirms
// the Go client's ConnectionState reports that exact negotiated group.
func runOpenSSLServerGoClient(certPath, keyPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := exec.CommandContext(ctx, "openssl", "s_server",
		"-cert", certPath,
		"-key", keyPath,
		"-www",
		"-tls1_3",
		"-groups", interopTLSGroup,
		"-provider", "default",
		"-provider", "oqsprovider",
		"-accept", strconv.Itoa(interopOpenSSLServerPort),
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

	if err := waitForPort(interopOpenSSLServerPort, 2*time.Second); err != nil {
		return fmt.Errorf("s_server never accepted connections: %w\nserver output:\n%s", err, serverOutput.String())
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("parse server cert into a trust pool")
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", interopOpenSSLServerPort), &tls.Config{
		RootCAs:          trust,
		ServerName:       "127.0.0.1",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	if err != nil {
		return fmt.Errorf("go client dial: %w\nserver output:\n%s", err, serverOutput.String())
	}
	defer func() { _ = conn.Close() }()

	curve := conn.ConnectionState().CurveID
	success := curve == tls.X25519MLKEM768
	fmt.Printf("interop-tls: openssl server + go client negotiated %s = %v\n", interopTLSGroup, success)
	if !success {
		return fmt.Errorf("go client recorded curve %d, want %d (X25519MLKEM768)", curve, tls.X25519MLKEM768)
	}
	return nil
}
