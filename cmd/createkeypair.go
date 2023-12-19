package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/urfave/cli/v2"
)

var createKeypairCommand = &cli.Command{
	Action:      createKeypairAction,
	Name:        "createkp",
	Usage:       "创建一个随机的密钥对",
	ArgsUsage:   "",
	Flags:       nil,
	Description: ``,
}

func createKeypairAction(ctx *cli.Context) error {
	kp := keypair.New()

	fmt.Printf("\n======================== Your new keypair was generated========================\n\n")
	fmt.Printf("Public key string:   %s\n", kp.PublicKey().HexString())
	fmt.Printf("Secret value hex string:   %s\n\n", kp.PrivateKey().HexString())
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must NEVER share the secret key with anyone! The key controls access to your funds!\n")

	return nil
}
