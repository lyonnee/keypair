package main

import (
	"fmt"

	"github.com/lyonnee/wallet"
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
	privKey := wallet.NewPrivateKey(nil)

	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public address of the key:   %s\n", privKey.Address())
	fmt.Printf("Secret value of the key:   %s\n\n", privKey.Hex())
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must NEVER share the secret key with anyone! The key controls access to your funds!\n")

	return nil
}
