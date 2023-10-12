package keypair

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	privK := NewPrivateKey(nil)
	signer := Signer{
		privK,
	}

	msg := []byte("ayiyayiayiyayiligedoligedo")
	signMsg := signer.SignMsg(msg)
	res := VerifyMsg(privK.GetPubKey(), msg, signMsg)
	assert.True(t, res)

	privK2 := NewPrivateKey(nil)
	res = VerifyMsg(privK2.GetPubKey(), msg, signMsg)
	assert.False(t, res)
}
