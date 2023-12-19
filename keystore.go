package keypair

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bytedance/sonic"
)

var (
	ErrDecrypt = errors.New("could not decrypt key with given password")
)

type Keystore struct {
	filepath string
	PubKey   string
	Crypto   CryptoJson `json:"crtpto"`
}

type CryptoJson struct {
	Cipher       string                 `json:"cipher"`
	CipherParams cipherparamsJSON       `json:"cipher_params"`
	CipherText   string                 `json:"cipher_text"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdf_params"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

func (ks *Keystore) Unlock(password string) (Keypair, error) {
	var kp Keypair

	k, err := DecryptData(ks.Crypto, password)
	if err != nil {
		return kp, err
	}

	kp = LoadFromPrivKeyBytes(k)
	return kp, nil
}

func (ks Keystore) Filepath() string {
	return ks.filepath
}

// 持久化
func (ks *Keystore) Persistence() error {
	var js []byte
	var err error
	if js, err = sonic.Marshal(ks); err != nil {
		return err
	}

	if err = os.WriteFile(ks.filepath, js, fs.ModeAppend); err != nil {
		return err
	}

	return nil
}

func NewKeystore(privKey PrivateKey, password, datadir string, useLightweightKDF bool) (string, error) {
	scryptN := StandardScryptN
	scryptP := StandardScryptP
	if useLightweightKDF {
		scryptN = LightScryptN
		scryptP = LightScryptP
	}

	var ks = new(Keystore)

	cryptoJson, err := EncryptData(privKey[:], []byte(password), scryptN, scryptP)
	if err != nil {
		return "", err
	}

	ks.PubKey = privKey.GetPubKey().HexString()
	ks.filepath = filepath.Join(datadir, ks.PubKey+".wallet")
	ks.Crypto = cryptoJson

	if err := ks.Persistence(); err != nil {
		return "", err
	}
	return ks.filepath, nil
}

func LoadKeystore(filepath string) (*Keystore, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var ks = new(Keystore)
	if err := sonic.Unmarshal(data, ks); err != nil {
		return nil, err
	}

	return ks, nil
}
