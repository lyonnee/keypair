package main

import (
	"fmt"
	"os"

	"github.com/lyonnee/wallet"
	"github.com/urfave/cli/v2"
)

var (
	createKeystoreCommand = &cli.Command{
		Action:    createKeystoreAction,
		Name:      "createks",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath>",
		Flags: []cli.Flag{
			passwordFlag,
			datadirFlag,
			lightweightKDFFlag,
		},
		Description: ``,
	}

	datadir     string
	datadirFlag = &cli.StringFlag{
		Name:        "datadir",
		Value:       "",
		DefaultText: "os.Getwd()",
		Aliases:     []string{"d"},
		Destination: &datadir,
		Action: func(ctx *cli.Context, s string) error {
			if datadir == "" {
				datadir, _ = os.Getwd()
			}

			return nil
		}}

	password     string
	passwordFlag = &cli.StringFlag{
		Name:        "password",
		Value:       "",
		DefaultText: "",
		Aliases:     []string{"pwd"},
		Destination: &password,
		Action:      nil,
	}

	useLightweightKDF  bool
	lightweightKDFFlag = &cli.BoolFlag{
		Name:        "lightweightKDF",
		Value:       false,
		DefaultText: "false",
		Aliases:     []string{"lkdf"},
		Destination: &useLightweightKDF,
		Action:      nil,
	}
)

func createKeystoreAction(ctx *cli.Context) error {
	privKey := wallet.NewPrivateKey(nil)
	filepath, err := wallet.NewKeystore(privKey, password, datadir, useLightweightKDF)
	if err != nil {
		return err
	}

	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public address of the key:   %s\n", privKey.Address())
	fmt.Printf("Keystore has saved to:   %s\n", filepath)
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must BACKUP your key file! Without the key, it's impossible to access account funds!\n")
	fmt.Printf("- You must REMEMBER your password! Without the password, it's impossible to decrypt the key!\n\n")

	return nil
}
