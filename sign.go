package keypair

import (
	"crypto/ed25519"
)

func SignMsgWithPrivKey(privKey PrivateKey, msg []byte) []byte {
	return ed25519.Sign(privKey.ToEd25519PrivKey(), msg)
}

func VerifyMsg(pubKey PublicKey, originMsg, signMsg []byte) bool {
	return ed25519.Verify(pubKey[:], originMsg, signMsg)
}
