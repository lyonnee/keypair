package keypair

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// EncryptCBC encrypt data using a key and IV with AES in CBC mode.
func EncryptCBC(data, iv, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	encryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedData, data)

	return
}

// DecryptCBC decrypt bytes using a key and IV with AES in CBC mode.
func DecryptCBC(data, iv, key []byte) (decryptedData []byte, err error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV length must equal block size: 16")
	}

	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	decryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(decryptedData, data)

	return
}
