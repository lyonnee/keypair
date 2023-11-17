Here is an enhanced README.md for the Go ED25519 wallet library with BIP39 and BIP32 compatibility:

# Go ED25519 Wallet

This is a Golang implementation of an ED25519 based asymmetric cryptography wallet library. 

## Features

- Generate ED25519 public/private key pairs
- Derive addresses from public keys  
- Sign and verify messages using keys
- Recover public key from signatures
- Implements HD wallet algorithms (seed, master keys, derivation etc.)
- Provides mnemonic phrase generation and recovery (inspired by BIP39)
- Supports encrypting/decrypting private keys (using passphrase and Scrypt)
- Implements a complete asymmetric crypto account system
- Compatible with BIP39 and BIP32 standards

## Usage Example

```go
	privk := keypair.NewPrivateKey(nil)
	pubk := privk.GetPubKey()
	addr := pubk.Address()
	fmt.Println(addr)

	fmt.Println("is valid addr: ", keypair.IsValidAddr(addr))
```

## Mnemonic Phrases

The library implements a BIP39-like mnemonic phrase algorithm to generate seeds and recover wallets. 

```go
// Generate mnemonic phrase
mnemonic := keypair.GenerateMnemonic(12,"cn")
```

Encryption uses PBKDF2 and Scrypt key derivation to harden security.

This library can be used to build ED25519 based cryptocurrency projects and applications. Contributions via issues and PRs are welcome!