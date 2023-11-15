package addressgen

import (
	"crypto/sha256"

	"github.com/lyonnee/keypair"
)

const HChain_CHECKSUM_LENGTH = 4
const HChain_PREFIX = "Hcc"

var GenHChainAddr keypair.GetAddrFunc = func(prefix, pubk []byte) string {
	// 1: 对公钥分别执行sha256,sha224哈希得到 pubkeyhash
	sha256PubKey := GenerateSha256PubKeyHash(pubk)
	versionPublickeyHash := sha256PubKey
	// 2: 对pubkeyhash执行sha256两次hash,取尾部部分字段做检验用
	sumHash := CheckSumHash(versionPublickeyHash, HChain_CHECKSUM_LENGTH)
	// 3: 拼接hashkey 和 校验hash
	finalHash := append(versionPublickeyHash, sumHash...)
	// 4: base58序列化
	base58Code := BtcBase58Encode(finalHash)
	// 5: 添加前缀
	address := append([]byte(HChain_PREFIX), base58Code...)
	return string(address)
}

func GenerateSha256PubKeyHash(publicKey []byte) []byte {
	sha256PubKey := sha256.Sum256(publicKey)
	sha224PubKey := sha256.Sum224(sha256PubKey[:])
	return sha224PubKey[:]
}
