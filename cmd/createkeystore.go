package main

import (
	"fmt"
	"os"

	"github.com/lyonnee/keypair"
	"github.com/urfave/cli/v2"
)

var (
	createKeystoreCommand = &cli.Command{
		Action:    createKeystoreAction,
		Name:      "createks",
		Usage:     "创建一组随机的非对称加密的密钥对, 设置密码, 可指定保存到地址",
		ArgsUsage: "",
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
		Usage:       "directory for the keystore",
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
		Usage:       "password for the keystore",
		Aliases:     []string{"p"},
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
	privKey := keypair.NewPrivateKey(nil)
	filepath, err := keypair.NewKeystore(privKey, password, datadir, useLightweightKDF)
	if err != nil {
		return err
	}

	fmt.Printf("\n======================== Your new key was generated========================\n\n")
	fmt.Printf("Public key hex string:   %s\n", privKey.GetPubKey().HexString())
	fmt.Printf("Keystore has saved to:   %s\n", filepath)
	fmt.Printf("- You can share your public address with anyone. Others need it to interact with you.\n")
	fmt.Printf("- You must BACKUP your key file! Without the key, it's impossible to access account funds!\n")
	fmt.Printf("- You must REMEMBER your password! Without the password, it's impossible to decrypt the key!\n\n")

	return nil
}
