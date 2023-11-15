package addressgen

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/lyonnee/keypair"
)

var GenEthAddr keypair.GetAddrFunc = func(version, pubk []byte) string {
	pubkhash := sha256.Sum256(pubk)
	address := "0x" + hex.EncodeToString(pubkhash[len(pubkhash)-20:])
	return address
}
