package keypair

var addresserGenerater Addresser

func SetAddresser(addrgen Addresser) {
	addresserGenerater = addrgen
}
