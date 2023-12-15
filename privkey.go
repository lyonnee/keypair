package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"

	"github.com/islishude/bip32"
)

const PrivateKeyLength int = ed25519.PrivateKeySize

type PrivateKey [PrivateKeyLength]byte

func (pk PrivateKey) GetPubKey() PublicKey {
	edprivk := pk.ToEd25519PrivKey()

	edpubk := edprivk.Public()
	var pubKey PublicKey
	copy(pubKey[:], edpubk.(ed25519.PublicKey))

	return pubKey
}

func (pk PrivateKey) NewChildKey(index uint32) PrivateKey {
	rootPrvKey := bip32.NewRootXPrv(pk[:])
	newXPrv := rootPrvKey.Derive(index)

	var newPrivkey PrivateKey
	copy(newPrivkey[:], newXPrv.Bytes())

	return newPrivkey
}

func (pk PrivateKey) ToEd25519PrivKey() ed25519.PrivateKey {
	var edprivk = make([]byte, ed25519.PrivateKeySize)
	copy(edprivk, pk.Bytes())

	return edprivk
}

func (pk PrivateKey) SignMsg(msg []byte) []byte {
	return ed25519.Sign(pk.ToEd25519PrivKey(), msg)
}

func (pk PrivateKey) HexString() string {
	return hex.EncodeToString(pk.Bytes())
}

func NewPrivateKey(seed []byte) PrivateKey {
	if seed == nil {
		seed = randSeed()
	}
	edprivk := ed25519.NewKeyFromSeed(seed)

	privKey, _ := bytesToPrivKey(edprivk)
	return privKey
}

func (pk PrivateKey) LoadFromHex(s string) (PrivateKey, error) {
	d, err := hex.DecodeString(s)
	if err != nil {
		return PrivateKey{}, err
	}

	return bytesToPrivKey(d)
}

func (pk PrivateKey) Bytes() []byte {
	return pk[:]
}

func (pk PrivateKey) LoadFromBytes(d []byte) (PrivateKey, error) {
	return bytesToPrivKey(d)
}

func (pk PrivateKey) Address() string {
	return pk.GetPubKey().Address()
}

func (pk PrivateKey) ToCurve25519() []byte {
	return ed25519PrivKeyToCurve25519(pk.Bytes())
}
func (pk PrivateKey) SharedSecret(pub []byte, decrypt bool) ([]byte, error) {
	return sharedSecret(pub, pk.Bytes(), true)
}

func bytesToPrivKey(d []byte) (PrivateKey, error) {
	var privKey PrivateKey
	copy(privKey[:], d)
	return privKey, nil
}

func randSeed() []byte {
	seed := make([]byte, 32)
	rand.Read(seed)

	return seed
}
