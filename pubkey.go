package wallet

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/islishude/bip32"
)

type PublicKey [PublicKeyLength]byte

const PublicKeyLength int = ed25519.PublicKeySize

var GetAddrFunc func([]byte) string

func (pk PublicKey) NewChildKey(index uint32) PublicKey {
	xPub := bip32.NewXPub(pk[:])
	newXPub := xPub.Derive(index)

	var newPubK PublicKey
	copy(newPubK[:], newXPub.Bytes())
	return newPubK
}

func (pk PublicKey) Hex() string {
	return hex.EncodeToString(pk[:])
}

func (pk PublicKey) Address() string {
	if GetAddrFunc == nil {
		return pk.Hex()
	}
	return GetAddrFunc(pk[:])
}

func (pk PublicKey) VerifyMsg(orginMsg, signMsg []byte) bool {
	return ed25519.Verify(pk[:], orginMsg, signMsg)
}
