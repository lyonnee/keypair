package main

import (
	"fmt"

	"github.com/lyonnee/keypair"
	"github.com/urfave/cli/v2"
)

var (
	createMnemonicCommond = &cli.Command{
		Action:    createHdWalletAction,
		Name:      "createmm",
		Usage:     "基于BIP39协议创建一组随机的助记词, 可指定生成密码, 可指定助记词数量, 可指定助记词语言",
		ArgsUsage: "",
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
		Aliases:     []string{"l"},
		Destination: &mnemonicLang,
		Action:      nil,
	}

	mnemonicQuantity     int
	mnemonicQuantityFlag = &cli.IntFlag{
		Name:        "mnemonicQuantity",
		Value:       12,
		Usage:       "quantity for the mnemonic",
		Aliases:     []string{"q"},
		Destination: &mnemonicQuantity,
		Action:      nil,
	}

	mnemonicPassword     string
	mnemonicPasswordFlag = &cli.StringFlag{
		Name:        "mnemonicPassword",
		Value:       "",
		DefaultText: "",
		Aliases:     []string{"p"},
		Destination: &mnemonicPassword,
		Action:      nil,
	}
)

func createHdWalletAction(ctx *cli.Context) error {
	words, err := keypair.GenerateMnemonic(mnemonicQuantity, mnemonicLang)
	if err != nil {
		return err
	}
	seed := keypair.ToSeed(words, mnemonicPassword)

	keypair.NewPrivateKey(seed)

	fmt.Printf("\n======================== Your new key was generated========================\n\n")
	fmt.Printf("Mnemonic words is:   %s\n", words)
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must BACKUP your mnemonic words! Without the mnemonic words, it's impossible to access account funds!\n")
	fmt.Printf("- You must REMEMBER your mnemonic words! Without the mnemonic words, it's impossible to decrypt the key!\n\n")

	return nil
}
