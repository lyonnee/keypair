package keypair

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

func ed25519PrivKeyToCurve25519(pk []byte) []byte {
	h := sha512.New()
	h.Write(ed25519.PrivateKey(pk).Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func ed25519PubKeyToCurve25519(pk []byte) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func SharedSecret(pubKey, privKey []byte, decrypt bool) ([]byte, error) {
	x25519PrivKey := ed25519PrivKeyToCurve25519(privKey)
	return sharedSecret(pubKey, x25519PrivKey, decrypt)
}

func sharedSecret(pub []byte, xPrivKey []byte, decrypt bool) ([]byte, error) {
	xPub, err := ed25519PubKeyToCurve25519(pub)
	if err != nil {
		return nil, err
	}

	secret, err := curve25519.X25519(xPrivKey, xPub)
	if err != nil {
		return nil, err
	}

	return secret, nil
}
