package addressgen

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/lyonnee/keypair"
	"golang.org/x/crypto/ripemd160"
)

const BTC_CHECKSUM_LENGTH = 4

var GenBtcAddr keypair.GetAddrFunc = func(version, pubk []byte) string {
	//1.ripemd160(sha256(publickey))
	ripPubKey := GenerateRipemd160PubKeyHash(pubk)
	//2.最前面添加一个字节的版本信息获得 versionPublickeyHash
	versionPublickeyHash := append(version, ripPubKey...)
	//3.sha256(sha256(versionPublickeyHash))  取最后四个字节的值
	tailHash := CheckSumHash(versionPublickeyHash, BTC_CHECKSUM_LENGTH)
	//4.拼接最终hash versionPublickeyHash + checksumHash
	finalHash := append(versionPublickeyHash, tailHash...)
	//进行base58加密
	address := BtcBase58Encode(finalHash)
	return string(address)
}

var IsVaildBtcAddress keypair.CheckAddressFunc = func(address string) bool {
	adddressByte := []byte(address)
	fullHash := BtcBase58Decode(adddressByte)
	if len(fullHash) != 25 {
		return false
	}
	prefixHash := fullHash[:len(fullHash)-BTC_CHECKSUM_LENGTH]
	tailHash := fullHash[len(fullHash)-BTC_CHECKSUM_LENGTH:]
	tailHash2 := CheckSumHash(prefixHash, BTC_CHECKSUM_LENGTH)
	if bytes.Compare(tailHash, tailHash2[:]) == 0 {
		return true
	} else {
		return false
	}
}

func GenerateRipemd160PubKeyHash(publicKey []byte) []byte {
	sha256PubKey := sha256.Sum256(publicKey)
	r := ripemd160.New()
	r.Write(sha256PubKey[:])
	ripPubKey := r.Sum(nil)

	return ripPubKey
}

func CheckSumHash(versionPublickeyHash []byte, hashLen int) []byte {
	versionPublickeyHashSha1 := sha256.Sum256(versionPublickeyHash)
	versionPublickeyHashSha2 := sha256.Sum256(versionPublickeyHashSha1[:])
	tailHash := versionPublickeyHashSha2[:hashLen]
	return tailHash
}

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func BtcBase58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)

	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	ReverseBytes(result)

	for _, b := range input {
		if b == 0x00 {
			result = append([]byte{b58Alphabet[0]}, result...)
		} else {
			break
		}
	}
	return result

}

func BtcBase58Decode(input []byte) []byte {
	result := big.NewInt(0)
	zeroBytes := 0
	for _, b := range input {
		if b != b58Alphabet[0] {
			break
		}
		zeroBytes++
	}
	payload := input[zeroBytes:]
	for _, b := range payload {
		charIndex := bytes.IndexByte(b58Alphabet, b)
		result.Mul(result, big.NewInt(int64(len(b58Alphabet))))
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	decoded := result.Bytes()
	decoded = append(bytes.Repeat([]byte{byte(0x00)}, zeroBytes), decoded...)

	return decoded
}

func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
