package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// caRotationCheck describes one certificate-chain verification performed
// after rotating from the classical to the post-quantum CA.
type caRotationCheck struct {
	desc         string // display description of what's being proven
	cert         string // certificate path being verified
	caFile       string // trust anchor(s) passed to `openssl verify -CAfile`
	wantVerified bool   // whether this chain is expected to verify
}

// runCARotationDemo rotates a CA from a classical (Ed25519) signing
// algorithm to a post-quantum (ML-DSA-65) one via a cross-signed
// transitional certificate, the same bridge pattern real CA/root
// rotations (e.g. web PKI root transitions) use so relying parties don't
// all need to adopt a new trust anchor on the same day. It then confirms:
// a certificate issued before the rotation still verifies against the old
// CA; a certificate issued after the rotation does *not* verify against
// the old CA alone, since the old CA never signed anything from the new
// CA; that same certificate *does* verify against the old CA's trust
// anchor once the cross-cert bridges the two, proving relying parties who
// haven't yet added the new PQ root still validate certificates issued
// under it; and that it verifies directly against the new CA too, for
// relying parties who have.
func runCARotationDemo() error {
	dir, err := os.MkdirTemp("", "pqlab-ca-rotation-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := func(name string) string { return filepath.Join(dir, name) }
	caExtensions := []string{
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
	}

	// 1. The classical CA, as it exists before rotation.
	oldCACrt, oldCAKey := path("old-ca.crt"), path("old-ca.key")
	if out, err := runOpenSSL(
		"req", "-x509", "-new", "-newkey", "ed25519",
		"-keyout", oldCAKey, "-out", oldCACrt,
		"-nodes", "-subj", "/CN=pq-migration-lab CA v1 (classical)", "-days", "1",
	); err != nil {
		return fmt.Errorf("create old (classical) CA: %w\n%s", err, out)
	}

	// 2. A leaf issued under the old CA before rotation, to later confirm
	// the rotation doesn't invalidate certificates already issued.
	legacyLeafCrt, err := issueLeaf(dir, "legacy-leaf", "ed25519", "/CN=legacy-server", oldCACrt, oldCAKey)
	if err != nil {
		return fmt.Errorf("issue pre-rotation legacy leaf: %w", err)
	}

	// 3. The new CA: a post-quantum keypair and self-signed root, so
	// relying parties who've already adopted it as a trust anchor can
	// verify certificates directly.
	newCACrt, newCAKey := path("new-ca.crt"), path("new-ca.key")
	newCASubj := "/CN=pq-migration-lab CA v2 (post-quantum)"
	if out, err := runOpenSSL(append([]string{
		"req", "-x509", "-new", "-newkey", "mldsa65",
		"-keyout", newCAKey, "-out", newCACrt,
		"-nodes", "-subj", newCASubj, "-days", "1",
		"-provider", "default", "-provider", "oqsprovider",
	}, caExtensions...)...); err != nil {
		return fmt.Errorf("create new (post-quantum) CA: %w\n%s", err, out)
	}

	// 4. Cross-sign the new CA's key under the old CA: a transitional
	// certificate carrying the new CA's subject and public key, but
	// signed by the old CA. This bridges trust: the new CA's
	// certificates can chain back to the already-trusted old root during
	// the transition, without every relying party needing to add the new
	// root as a trust anchor on day one.
	newCACSR := path("new-ca.csr")
	if out, err := runOpenSSL(append([]string{
		"req", "-new", "-key", newCAKey, "-out", newCACSR, "-subj", newCASubj,
		"-provider", "default", "-provider", "oqsprovider",
	}, caExtensions...)...); err != nil {
		return fmt.Errorf("create new CA CSR for cross-signing: %w\n%s", err, out)
	}
	// x509 -req has no -addext of its own: it only carries over
	// extensions the CSR itself requested, hence -copy_extensions here
	// and -addext on the CSR above rather than on this command.
	crossCrt := path("cross.crt")
	if out, err := runOpenSSL(
		"x509", "-req", "-in", newCACSR, "-out", crossCrt,
		"-CA", oldCACrt, "-CAkey", oldCAKey, "-CAcreateserial", "-days", "1",
		"-copy_extensions", "copy",
		"-provider", "default", "-provider", "oqsprovider",
	); err != nil {
		return fmt.Errorf("cross-sign new CA under old CA: %w\n%s", err, out)
	}

	// Bundle the cross-cert together with the old CA into one trust file:
	// this is the trust store of a relying party who still only trusts
	// the old root. `openssl verify -untrusted` builds the same chain but
	// hits a decode error here: oqs-provider's ML-DSA-65 public key
	// isn't re-fetched with provider awareness on that path in this
	// openssl/oqs-provider combination, so the intermediate is supplied
	// via -CAfile instead, which doesn't hit it.
	oldTrustBundle := path("old-trust-bundle.crt")
	if err := concatFiles(oldTrustBundle, crossCrt, oldCACrt); err != nil {
		return fmt.Errorf("build old-CA trust bundle: %w", err)
	}

	// 5. A leaf issued under the new CA after rotation.
	newLeafCrt, err := issueLeaf(dir, "new-leaf", "mldsa65", "/CN=pq-server-v2", newCACrt, newCAKey)
	if err != nil {
		return fmt.Errorf("issue post-rotation leaf: %w", err)
	}

	checks := []caRotationCheck{
		{desc: "pre-rotation legacy leaf still verifies against the old CA", cert: legacyLeafCrt, caFile: oldCACrt, wantVerified: true},
		{desc: "post-rotation leaf against the old CA alone (no cross-cert) fails to verify", cert: newLeafCrt, caFile: oldCACrt, wantVerified: false},
		{desc: "post-rotation leaf verifies directly against the new CA", cert: newLeafCrt, caFile: newCACrt, wantVerified: true},
		{desc: "post-rotation leaf also verifies against the old CA via the cross-cert", cert: newLeafCrt, caFile: oldTrustBundle, wantVerified: true},
	}

	for _, c := range checks {
		out, verifyErr := runOpenSSL("verify", "-CAfile", c.caFile, "-provider", "default", "-provider", "oqsprovider", c.cert)
		verified := verifyErr == nil && bytes.Contains(out, []byte("OK"))
		fmt.Printf("ca-rotation: %s: verified = %v (expected %v)\n", c.desc, verified, c.wantVerified)
		if verified != c.wantVerified {
			return fmt.Errorf("%s: expected verified=%v, got %v: %w\n%s", c.desc, c.wantVerified, verified, verifyErr, out)
		}
	}

	return nil
}

// concatFiles writes the concatenated contents of srcs to dst, in order.
func concatFiles(dst string, srcs ...string) error {
	var buf bytes.Buffer
	for _, src := range srcs {
		content, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", src, err)
		}
		buf.Write(content)
	}
	return os.WriteFile(dst, buf.Bytes(), 0o600)
}
