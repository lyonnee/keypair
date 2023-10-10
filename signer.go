package wallet

import (
	"crypto/ed25519"
)

type Signer struct {
	key PrivateKey
}

func (s *Signer) SignMsg(msg []byte) []byte {
	return SignMsgWithPrivKey(s.key, msg)
}

func SignMsgWithPrivKey(privKey PrivateKey, msg []byte) []byte {
	return ed25519.Sign(privKey.ToEd25519PrivKey(), msg)
}

func VerifyMsg(pubKey PublicKey, orginMsg, signMsg []byte) bool {
	return ed25519.Verify(pubKey[:], orginMsg, signMsg)
}
