package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Usage: "Blockchain wallet create interface",
		Action: func(ctx *cli.Context) error {
			return nil
		},
		Commands: []*cli.Command{
			createKeypairCommand,
			createKeystoreCommand,
			createMnemonicCommond,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
