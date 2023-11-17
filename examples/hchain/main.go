package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
)

func main() {
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := pubk.Address()
	fmt.Println(addr)

	fmt.Println("is valid addr: ", keypair.IsValidAddr(addr))
}
