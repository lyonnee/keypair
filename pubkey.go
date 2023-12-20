package keypair

import (
	"crypto/ed25519"
	"encoding/hex"
)

type PublicKey [PublicKeyLength]byte

const PublicKeyLength int = ed25519.PublicKeySize

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
