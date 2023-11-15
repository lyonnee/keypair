package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/lyonnee/keypair/addressgen"
)

func main() {
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := addressgen.GenEthAddr(nil, pubk.Bytes())
	fmt.Println("new eth address:", addr)
}
