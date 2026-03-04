package agility

// KEMFactory is a registrable, named key-encapsulation scheme: classical,
// post-quantum, or hybrid. Registry entries are factories rather than live
// sessions: each handshake gets its own KEMSession so concurrent handshakes
// don't share key material.
type KEMFactory interface {
	Algorithm
	// New starts a fresh KEM session. Callers must Close it when done.
	New() (KEMSession, error)
}

// KEMSession is one stateful KEM handshake. The typical flow is:
//
//	initiator                          responder
//	pub, _ := s.GenerateKeyPair()  -->
//	                               <--  ct, ss, _ := s.Encapsulate(pub)
//	ss, _ := s.Decapsulate(ct)
//
// The session that calls GenerateKeyPair is the one that later calls
// Decapsulate; the peer that receives the public key calls Encapsulate.
// Implementations may hold private key material internally rather than
// threading it through method arguments (this matches liboqs's KEM object
// model, where the secret key never leaves the session).
type KEMSession interface {
	GenerateKeyPair() (publicKey []byte, err error)
	Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
	Close() error
}
