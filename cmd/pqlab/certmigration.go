package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// certMigrationLeaf describes one leaf certificate issued in the demo.
type certMigrationLeaf struct {
	name    string // display name, e.g. "post-quantum (ML-DSA-65)"
	newkey  string // openssl -newkey algorithm name, and this leaf's file basename
	subject string
}

var certMigrationLeaves = []certMigrationLeaf{
	{name: "classical (Ed25519)", newkey: "ed25519", subject: "/CN=classical-server"},
	{name: "post-quantum (ML-DSA-65)", newkey: "mldsa65", subject: "/CN=pq-server"},
}

// runCertMigrationDemo issues two leaf certificates (one classical, one
// post-quantum) under the same classical CA, and confirms both verify
// against it. This demonstrates that a CA doesn't need to migrate its own
// signing algorithm before it can start issuing post-quantum leaf
// certificates: the CA's signing algorithm and a leaf's key algorithm are
// independent.
func runCertMigrationDemo() error {
	dir, err := os.MkdirTemp("", "pqlab-cert-migration-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	caCrt := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if out, err := runOpenSSL(
		"req", "-x509", "-new", "-newkey", "ed25519",
		"-keyout", caKey, "-out", caCrt,
		"-nodes", "-subj", "/CN=pq-migration-lab CA", "-days", "1",
	); err != nil {
		return fmt.Errorf("create CA: %w\n%s", err, out)
	}

	for _, leaf := range certMigrationLeaves {
		crt, err := issueLeaf(dir, leaf.newkey, leaf.newkey, leaf.subject, caCrt, caKey)
		if err != nil {
			return fmt.Errorf("issue %s leaf: %w", leaf.name, err)
		}

		out, verifyErr := runOpenSSL("verify", "-CAfile", caCrt, "-provider", "default", "-provider", "oqsprovider", crt)
		verified := verifyErr == nil && bytes.Contains(out, []byte("OK"))
		fmt.Printf("cert-migration: %s leaf issued by classical CA, verified = %v\n", leaf.name, verified)
		if !verified {
			return fmt.Errorf("leaf certificate for %s did not verify against the CA: %w\n%s", leaf.name, verifyErr, out)
		}
	}

	return nil
}

// issueLeaf creates a CSR (key algorithm newkey, distinguished name
// subject) and issues a leaf certificate for it under caCrt/caKey, writing
// <dir>/<name>.{key,csr,crt}. It returns the issued certificate's path.
//
// -provider oqsprovider is only needed for post-quantum key algorithms,
// but passing it unconditionally is harmless and keeps every call site
// identical apart from newkey/subject.
func issueLeaf(dir, name, newkey, subject, caCrt, caKey string) (string, error) {
	key := filepath.Join(dir, name+".key")
	csr := filepath.Join(dir, name+".csr")
	crt := filepath.Join(dir, name+".crt")

	if out, err := runOpenSSL(
		"req", "-new", "-newkey", newkey,
		"-keyout", key, "-out", csr, "-nodes", "-subj", subject,
		"-provider", "default", "-provider", "oqsprovider",
	); err != nil {
		return "", fmt.Errorf("create CSR: %w\n%s", err, out)
	}

	if out, err := runOpenSSL(
		"x509", "-req", "-in", csr, "-out", crt,
		"-CA", caCrt, "-CAkey", caKey, "-CAcreateserial", "-days", "1",
		"-provider", "default", "-provider", "oqsprovider",
	); err != nil {
		return "", fmt.Errorf("issue certificate: %w\n%s", err, out)
	}
	return crt, nil
}

func runOpenSSL(args ...string) ([]byte, error) {
	return exec.Command("openssl", args...).CombinedOutput()
}
