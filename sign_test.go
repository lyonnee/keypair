package keypair

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	kp := New()

	msg := []byte("ayiyayiayiyayiligedoligedo")
	signMsg := kp.SignMsg(msg)
	res := VerifyMsg(kp.PublicKey(), msg, signMsg)
	assert.True(t, res)

	privK2 := NewPrivateKey(nil)
	res = VerifyMsg(privK2.GetPubKey(), msg, signMsg)
	assert.False(t, res)
}
