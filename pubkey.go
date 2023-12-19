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

func (pk PublicKey) VerifyMsg(originMsg, signMsg []byte) bool {
	return ed25519.Verify(pk[:], originMsg, signMsg)
}

func (pk PublicKey) Bytes() []byte {
	return pk[:]
}

func (pk *PublicKey) LoadFromBytes(d []byte) error {
	var err error
	pk, err = bytesToPubKey(d)
	return err
}

func bytesToPubKey(d []byte) (*PublicKey, error) {
	var pubKey PublicKey
	copy(pubKey[:], d)
	return &pubKey, nil
}
