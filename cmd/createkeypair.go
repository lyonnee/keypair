package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/urfave/cli/v2"
)

var createKeypairCommand = &cli.Command{
	Action:      createKeypairAction,
	Name:        "createkp",
	Usage:       "Bootstrap and initialize a new genesis block",
	ArgsUsage:   "<genesisPath>",
	Flags:       nil,
	Description: ``,
}

func createKeypairAction(ctx *cli.Context) error {
	privKey := keypair.NewPrivateKey(nil)

	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public key hex string:   %s\n", privKey.GetPubKey().HexString())
	fmt.Printf("Secret value hex string:   %s\n\n", privKey.HexString())
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must NEVER share the secret key with anyone! The key controls access to your funds!\n")

	return nil
}
