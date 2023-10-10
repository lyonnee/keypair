package wallet

import (
	"crypto/sha512"

	"github.com/dongri/go-mnemonic"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	EntropyBits128 uint16 = 128
	EntropyBits160 uint16 = 160
	EntropyBits192 uint16 = 192
	EntropyBits224 uint16 = 224
	EntropyBits256 uint16 = 256
)

func GenerateMnemonic(mnemonicQuantity int, mnemonicLang string) (string, error) {
	var strength uint16
	switch mnemonicQuantity {
	case 15:
		strength = EntropyBits160
	case 18:
		strength = EntropyBits192
	case 21:
		strength = EntropyBits224
	case 24:
		strength = EntropyBits256
	case 12:
	default:
		strength = EntropyBits128
	}

	var language mnemonic.Language
	switch mnemonicLang {
	case "cn":
		language = mnemonic.LanguageChineseSimplified
	case "en":
	default:
		language = mnemonic.LanguageEnglish
	}

	return mnemonic.GenerateMnemonic(strength, language)
}

func ToSeed(mnemonic, password string) []byte {
	normalizedMnemonic := norm.NFKD.String(mnemonic)
	normalizedPassword := norm.NFKD.String(password)
	return pbkdf2.Key([]byte(normalizedMnemonic), []byte("mnemonic"+normalizedPassword), 2048, 32, sha512.New)
}
