package keypair

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSharedSecret(t *testing.T) {
	a := NewKeypair()

	b := NewKeypair()

	ass, err := a.SharedSecret(b.PublicKey(), true)
	assert.NoError(t, err)

	bss, err := b.SharedSecret(a.PublicKey(), true)
	assert.NoError(t, err)

	assert.Equal(t, ass, bss)
}
