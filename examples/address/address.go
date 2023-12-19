package main

import (
	"errors"

	"github.com/lyonnee/keypair"
)

const Addr_Length = 44

var prefix string = "Hcc"
var Err_Invalid_Addr = errors.New("invalid address")

func genAddress(pubk []byte) string {
	return prefix + string(Base58Encode(pubk))
}

func IsValidAddr(addr string) bool {
	if prefix != addr[:len(prefix)] {
		return false
	}

	if len(addr[len(prefix):]) != Addr_Length {
		return false
	}

	return true
}

func AddrToPubKey(addr string) (keypair.PublicKey, error) {
	var pubk keypair.PublicKey
	if prefix != addr[:len(prefix)] {
		return pubk, Err_Invalid_Addr
	}

	if len(addr[len(prefix):]) != Addr_Length {
		return pubk, Err_Invalid_Addr
	}

	b := Base58Decode([]byte(addr))
	copy(pubk[:], b)

	return pubk, nil
}
