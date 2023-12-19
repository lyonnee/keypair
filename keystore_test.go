package keypair

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeystore(t *testing.T) {
	privKey := NewPrivateKey(nil)
	t.Log(privKey.GetPubKey().HexString())
	datadir, _ := os.Getwd()

	filepath, _ := NewKeystore(privKey, "123456", datadir, false)

	ks, err := LoadKeystore(filepath)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := ks.Unlock("1234")
	assert.Error(t, err)

	pk, err = ks.Unlock("123456")
	assert.NoError(t, err)
	t.Log(pk.pubKey.HexString())
}
