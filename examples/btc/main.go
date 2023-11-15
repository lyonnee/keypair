package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/lyonnee/keypair/addressgen"
)

var NetVersion = []byte{0x00}

func main() {
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := addressgen.GenBtcAddr(NetVersion, pubk.Bytes())

	if !addressgen.IsVaildBtcAddress(addr) {
		fmt.Println("invalid btc address")
	}

	fmt.Println("new btc address:", addr)
}
