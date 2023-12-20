package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/curve25519"
)

const PrivateKeyLength int = ed25519.PrivateKeySize

type PrivateKey [PrivateKeyLength]byte

func (pk PrivateKey) GetPubKey() PublicKey {
	edPrivKey := pk.ToEd25519PrivKey()

	edPubKey := edPrivKey.Public()
	var pubKey PublicKey
	copy(pubKey[:], edPubKey.(ed25519.PublicKey))

	return pubKey
}

func (pk PrivateKey) ToEd25519PrivKey() ed25519.PrivateKey {
	var edPrivKey = make([]byte, ed25519.PrivateKeySize)
	copy(edPrivKey, pk.Bytes())

	return edPrivKey
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
	edPrivKey := ed25519.NewKeyFromSeed(seed)

	privKey, _ := bytesToPrivKey(edPrivKey)
	return privKey
}

func (pk *PrivateKey) LoadFromHex(s string) error {
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	return pk.LoadFromBytes(d)
}

func (pk *PrivateKey) Bytes() []byte {
	return pk[:]
}

func (pk *PrivateKey) LoadFromBytes(d []byte) error {
	btp, err := bytesToPrivKey(d)
	if err != nil {
		return err
	}

	pk = &btp
	return nil
}

func (pk *PrivateKey) toCurve25519() []byte {
	h := sha512.New()
	h.Write(pk.ToEd25519PrivKey().Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
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
