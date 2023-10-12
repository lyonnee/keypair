package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/urfave/cli/v2"
)

var (
	createHdWalletCommond = &cli.Command{
		Action:    createHdWalletAction,
		Name:      "createhw",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath>",
		Flags: []cli.Flag{
			mnemonicLangFlag,
			mnemonicQuantityFlag,
			mnemonicPasswordFlag,
		},
		Description: ``,
	}

	mnemonicLang     string
	mnemonicLangFlag = &cli.StringFlag{
		Name:        "mnemonicLang",
		Value:       "cn",
		Usage:       "language for the mnemonic",
		Destination: &mnemonicLang,
		Action:      nil,
	}

	mnemonicQuantity     int
	mnemonicQuantityFlag = &cli.IntFlag{
		Name:        "mnemonicQuantity",
		Value:       12,
		Usage:       "quantity for the mnemonic",
		Aliases:     []string{"mq"},
		Destination: &mnemonicQuantity,
		Action:      nil,
	}

	mnemonicPassword     string
	mnemonicPasswordFlag = &cli.StringFlag{
		Name:        "mnemonicPassword",
		Value:       "",
		DefaultText: "",
		Destination: &mnemonicPassword,
		Action:      nil,
	}
)

func createHdWalletAction(ctx *cli.Context) error {
	words, _ := keypair.GenerateMnemonic(mnemonicQuantity, mnemonicLang)
	seed := keypair.ToSeed(words, mnemonicPassword)

	privKey := keypair.NewPrivateKey(seed)

	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Mnemonic words is:   %s\n", words)
	for i := uint32(0); i < 10; i++ {
		newPrivkey := privKey.NewChildKey(i)
		fmt.Printf("Child index %d, Public key hex string:   %s\n", i, newPrivkey.GetPubKey().HexString())
	}
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must BACKUP your mnemonic words! Without the mnemonic words, it's impossible to access account funds!\n")
	fmt.Printf("- You must REMEMBER your mnemonic words! Without the mnemonic words, it's impossible to decrypt the key!\n\n")

	return nil
}
