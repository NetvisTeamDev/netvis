package main

// Signed answers.
//
// Hardcoding the server address stops someone editing a config file to
// point netvis at a server of their own. It does NOT stop someone who has
// Administrator - which netvis requires anyway - from installing their own
// root certificate, redirecting netvis.cc in the hosts file, and answering
// "licensed" to everything. TLS can't help there: the fake certificate is
// signed by a root the machine now trusts.
//
// So the answer itself is signed, with a key that never leaves this server,
// and the client checks that signature against a public key compiled into
// the binary. Whoever the client is actually talking to is then irrelevant:
// only this server can produce an answer it will accept. Forging one means
// finding the private key, not owning the network path.
//
// Replay is handled by the client generating a random nonce per request and
// the signature covering it, so a recorded "yes" can't be played back
// tomorrow, or against a different machine.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// ECDSA P-256 rather than Ed25519: Windows can verify P-256 through CNG on
// every supported version, while Ed25519 support only arrived recently.
// Signatures are raw r||s (64 bytes), which is the shape CNG expects - not
// the ASN.1 wrapping Go produces by default.

const sigMessagePrefix = "netvis-auth-v1"

func parseSigningKey(hexKey string) (*ecdsa.PrivateKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("response_private_key must be 64 hex characters")
	}
	d := new(big.Int).SetBytes(raw)
	curve := elliptic.P256()
	if d.Sign() == 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("response_private_key is not a valid P-256 scalar")
	}
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(raw)
	return priv, nil
}

// signAnswer produces the signature the client verifies. The message binds
// the answer to one machine, one expiry and one nonce - change any of them
// and the signature stops matching.
func signAnswer(priv *ecdsa.PrivateKey, hwid, expiresAt, nonce string) (string, error) {
	msg := fmt.Sprintf("%s|%s|%s|%s", sigMessagePrefix, hwid, expiresAt, nonce)
	digest := sha256.Sum256([]byte(msg))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return hex.EncodeToString(out), nil
}

// cmdGenKeys makes a fresh signing key. The private half goes in
// config.json on the server; the public half gets compiled into the client.
func cmdGenKeys() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	d := make([]byte, 32)
	priv.D.FillBytes(d)

	pub := make([]byte, 64)
	priv.PublicKey.X.FillBytes(pub[:32])
	priv.PublicKey.Y.FillBytes(pub[32:])

	fmt.Println("Put this in config.json on the server (keep it secret):")
	fmt.Printf("  \"response_private_key\": \"%s\"\n\n", hex.EncodeToString(d))
	fmt.Println("Put this in src/license.cpp in the client, then rebuild:")
	fmt.Printf("  const char* const kServerPublicKey =\n      \"%s\";\n\n", hex.EncodeToString(pub))
	fmt.Println("Order matters: configure the server first, then ship the client.")
	fmt.Println("A client built with this key rejects answers from a server without it.")
}
