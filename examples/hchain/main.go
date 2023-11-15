package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/lyonnee/keypair/addressgen"
)

func main() {
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := addressgen.GenHChainAddr(nil, pubk.Bytes())
	fmt.Println(addr)
}
