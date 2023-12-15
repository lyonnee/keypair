package keypair

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSharedSecret(t *testing.T) {
	a := NewPrivateKey(nil)
	t.Log(hex.EncodeToString(a.Bytes()))

	b := NewPrivateKey(nil)
	t.Log(hex.EncodeToString(b.Bytes()))

	ass, err := a.SharedSecret(b.GetPubKey().Bytes(), true)
	assert.NoError(t, err)

	bss, err := b.SharedSecret(a.GetPubKey().Bytes(), true)
	assert.NoError(t, err)

	assert.Equal(t, ass, bss)
}
