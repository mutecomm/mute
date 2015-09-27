Ciphersuites
------------


### Default ciphersuite

```
ECIES25519 KDF3 AES-CTR256 SHA512-HMAC ED25519 ECDHE25519
```

- Static Key Agreement: ECIES over curve25519 (TODO: not used anymore!)
- Key derivation function: KDF3
- Symmetric encryption: AES-256 in counter mode
- Integrity protection: SHA-512 HMAC
- Signature generation: Ed25519
- Forward secure key agreement: ECDHE over curve25519


### Algos/Protos

- ECDSA (key signature, exchange signature). Included in Go.
- ECIES (first contact messages). Needs to be implemented (in snippets folder).
- ECDH (PFS key agreement). Probably included in Go, but not exposed.
  Hint: crypto/tls/key_agreement.go.
	Plain implementation: github.com/tang0th/go-ecdh. See snippets.
- NaCL-box (curve25519 salsa20 poly1305)
- AES-256 CBC (messages, ECIES). Included in Go.
- AES-256 CTR (messages). Included in Go.
- SHA-512 (keyserver). Included in Go.
- SHA-512 HMAC (messages, ECIES). Included in Go.
- TLS 1.2 (not included) with TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  or TLS 1.0
  (included in Go) with TLS_ECDHE_ECDSA_AES_256_CBC_SHA_256.
- SKDF secure key derivation function. Use KDF3, see:
  http://www.di-mgt.com.au/cryptoKDFs.html
- ED25519 signature algorithm. Available for Go.
  http://godoc.org/github.com/agl/ed25519. In snippets folder.
- CSPRNG: Fortuna with AES256, SHA256, /dev/urandom. See snippets folder for
  example (don't use code).

### Encodings

- Base64 (message encoding, UID-Message encoding).
- Hexadecimal encoding.


### CKDF: cheap key derivation function

```
k1, k2 = CKDF(key) {
	a  = SHA512(key)
	a1 = a[0, (hashsize / 2)] | a[0, (hashsize / 2)]
	a2 = a[(hashsize / 2), hashsize] | a[(hashsize / 2), hashsize]
	// paddings 0x5c and 0x36 are repeated into a bitfield of hashsize for k1:
	k1 = SHA512( a1 ^ [0x5c * hashsize] | SHA512( a2 ^ [0x36 * hashsize] ))
	// swap a1 and a2 for k2:
	k2 = SHA512( a2 ^ [0x5c * hashsize] | SHA512( a1 ^ [0x36 * hashsize] ))
	return k1, k2
}
```


### Asymmetric encryption without sender authentication

For encrypting messages from the client to the Mix, asymmetric encryption is
necessary that relies only on the client's knowledge of the Mix's public key.
Two variants are defined: Use of NaCLBox as implemented or use of generic ECIES.
For both, the wrapper functions are defined below.


#### NaCL-Box: ASYM_Encrypt & ASYM_Decrypt functions

```
encrypted_message = ASYM_Encrypt (cleartext, peersPublicKey) {
	CipherSuite = "NACLBox curve25519 xsalsa20 poly1305"
	nonce: UNIQUE, random, long 192bit
	myPubKey, myPrivateKey = NaCLbox_GenerateKey()
	ciphertext = NaCLBox_Seal(cleartext, nonce, peersPublicKey, myPrivateKey)
	encrypted_message = json_struct{
			CipherSuit,
			myPubKey,
			nonce,
			ciphertext
		}
	return encrypted_message
}
```

```
decrypted_message = ASYM_Decrypt (encrypted_message, myPrivateKey) {
	Ciphersuite, peersPublicKey, nonce, ciphertext = parse(encrypted_message)
	assert Ciphersuite == "NACLBox curve25519 xsalsa20 poly1305"
	decrypted_message = NAaCLBox_Open(ciphertext, nonce, peersPublicKey, myPrivateKey)
	return decrypted_message
}
```


#### ECIES: ASYM_Encrypt & ASYM_Decrypt functions

```
encrypted_message = ASYM_Encrypt (cleartext, peersPublicKey) {
	CipherSuite = "ECIES25519 KDF3 aes-ctr256 sha256-hmac"
	ciphertext = ECIES_Seal(cleartext, peersPublicKey)
	encrypted_message = json_struct{
			CipherSuite,
			ciphertext
		}
	return encrypted_message
}
```

```
decrypted_message = ASYM_Decrypt (encrypted_message, myPrivateKey) {
	Ciphersuite, ciphertext = parse(encrypted_message)
	assert Ciphersuite == "ECIES25519 KDF3 aes-ctr256 sha256-hmac"
	decrypted_message = ECIES_Open(ciphertext, myPrivateKey)
	return decrypted_message
}
```
