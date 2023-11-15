package keypair

type Addresser interface {
	GetAddr(prefix []byte, pubk []byte) string
}

type GetAddrFunc func(prefix []byte, pubk []byte) string

func (fn GetAddrFunc) GetAddr(prefix []byte, pubk []byte) string {
	return fn(prefix, pubk)
}

type AddressChecker interface {
	CheckAddress(addr string) bool
}

type CheckAddressFunc func(addr string) bool

func (fn CheckAddressFunc) CheckAddress(addr string) bool {
	return fn(addr)
}
