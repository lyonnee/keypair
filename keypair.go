package keypair

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

func New() Keypair {
	newPk := NewPrivateKey(nil)
	return Keypair{
		privKey: newPk,
		pubKey:  newPk.GetPubKey(),
	}
}

func LoadFromSeed(seed []byte) Keypair {
	pk := NewPrivateKey(seed)

	return Keypair{
		privKey: pk,
		pubKey:  pk.GetPubKey(),
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