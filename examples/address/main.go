package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
)

func main() {
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := genAddress(pubk.Bytes())
	fmt.Println(addr)

	fmt.Println("is valid addr: ", IsValidAddr(addr))
}
