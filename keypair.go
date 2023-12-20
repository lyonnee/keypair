package keypair

import "path/filepath"

type Keypair struct {
	privKey PrivateKey
	pubKey  PublicKey
}

func (kp Keypair) PrivateKey() PrivateKey {
	return kp.privKey
}

func (kp Keypair) PublicKey() PublicKey {
	return kp.pubKey
}

func (kp Keypair) SignMsg(msg []byte) []byte {
	return SignMsgWithPrivKey(kp.privKey, msg)
}

func (kp Keypair) SharedSecret(pubKey PublicKey, decrypt bool) ([]byte, error) {
	return sharedSecret(pubKey.Bytes(), kp.privKey.toCurve25519(), true)
}

func (kp Keypair) SaveAsKeystore(password, datadir string, useLightweightKDF bool) (string, error) {
	scryptN := StandardScryptN
	scryptP := StandardScryptP
	if useLightweightKDF {
		scryptN = LightScryptN
		scryptP = LightScryptP
	}

	var ks = new(Keystore)

	cryptoJson, err := EncryptData(kp.PrivateKey().Bytes(), []byte(password), scryptN, scryptP)
	if err != nil {
		return "", err
	}

	ks.PubKey = kp.PublicKey().HexString()
	ks.filepath = filepath.Join(datadir, ks.PubKey+".wallet")
	ks.Crypto = cryptoJson

	if err := ks.Persistence(); err != nil {
		return "", err
	}
	return ks.filepath, nil
}

func New(seed []byte) Keypair {
	newPk := NewPrivateKey(seed)
	return Keypair{
		privKey: newPk,
		pubKey:  newPk.GetPubKey(),
	}
}

func LoadFromPrivKeyBytes(privKey []byte) Keypair {
	pk := new(PrivateKey)
	pk.LoadFromBytes(privKey)

	return Keypair{
		privKey: *pk,
		pubKey:  pk.GetPubKey(),
	}
}

func LoadFromPrivKeyHexString(s string) Keypair {
	pk := new(PrivateKey)
	pk.LoadFromHex(s)

	return Keypair{
		privKey: *pk,
		pubKey:  pk.GetPubKey(),
	}
}
