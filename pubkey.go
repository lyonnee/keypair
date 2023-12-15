package keypair

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/islishude/bip32"
)

type PublicKey [PublicKeyLength]byte

const PublicKeyLength int = ed25519.PublicKeySize

func (pk PublicKey) NewChildKey(index uint32) PublicKey {
	xPub := bip32.NewXPub(pk.Bytes())
	newXPub := xPub.Derive(index)

	var newPubK PublicKey
	copy(newPubK[:], newXPub.Bytes())
	return newPubK
}

func (pk PublicKey) HexString() string {
	return hex.EncodeToString(pk.Bytes())
}

func (pk PublicKey) VerifyMsg(orginMsg, signMsg []byte) bool {
	return ed25519.Verify(pk[:], orginMsg, signMsg)
}

func (pk PublicKey) Bytes() []byte {
	return pk[:]
}

func (pk PublicKey) LoadFromBytes(d []byte) (PublicKey, error) {
	return bytesToPubKey(d)
}

func (pk PublicKey) Address() string {
	return genAddress(pk.Bytes())
}

func (pk PublicKey) ToCurve25519() ([]byte, error) {
	return ed25519PubKeyToCurve25519(pk.Bytes())
}

func bytesToPubKey(d []byte) (PublicKey, error) {
	var pubKey PublicKey
	copy(pubKey[:], d)
	return pubKey, nil
}
