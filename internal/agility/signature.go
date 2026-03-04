package agility

// SignatureFactory is a registrable, named signature scheme: classical
// or post-quantum. Like KEMFactory, registry entries are factories: each
// signer/verifier gets its own SignatureSession.
type SignatureFactory interface {
	Algorithm
	// New starts a fresh signature session. Callers must Close it when done.
	New() (SignatureSession, error)
}

// SignatureSession is one signature scheme instance. A signer calls
// GenerateKeyPair then Sign; a verifier only ever needs Verify, and
// doesn't require its own keypair: the public key comes from whoever
// signed the message.
type SignatureSession interface {
	GenerateKeyPair() (publicKey []byte, err error)
	Sign(message []byte) (signature []byte, err error)
	Verify(message, signature, publicKey []byte) (bool, error)
	Close() error
}
