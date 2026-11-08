// Package dbcrypt encrypts database columns with a key from the environment, so a copy of the
// database alone doesn't reveal them. Encrypted columns are BYTEA, and model fields use
// EncryptedString or EncryptedBytes, which are encrypted when they're inserted and decrypted when
// they're scanned. Init must be called before any encrypted column is read or written.
//
// A stored value is a version byte, then AES-256-GCM's random nonce, ciphertext and tag. The version
// is for the key and format a value was encrypted with, so the key can be rotated later.
package dbcrypt

import (
	"crypto/cipher"
	"database/sql/driver"
)

// KeyEnvVar is the environment variable the key is read from. It's base64 for 32 random bytes. It's
// only read from the environment, since command-line flags can be seen in process listings.
const KeyEnvVar = "DB_ENCRYPTION_KEY"

// 256-bit key
const keyLength = 32

// version is the first byte of every stored value
const version byte = 0x01

var aesKey cipher.AEAD

// EncryptedString is a string stored encrypted. It can't be NULL, so nullable columns use
// *EncryptedString.
type EncryptedString string

// EncryptedBytes is a byte slice stored encrypted. A nil slice is stored as NULL, and NULL is scanned
// as nil.
type EncryptedBytes []byte

func (str *EncryptedString) Scan(src any) error {
	plain, err := open(src)
	if err != nil {
		return err
	}

	*str = EncryptedString(plain)

	return nil
}

func (str EncryptedString) Value() (driver.Value, error) {
	return seal([]byte(str))
}

func (b *EncryptedBytes) Scan(src any) error {
	// NULL scans as nil, the reverse of Value
	if src == nil {
		*b = nil
		return nil
	}

	plain, err := open(src)
	if err != nil {
		return err
	}

	// GCM decrypts an empty value to nil, which Value would store as NULL
	if plain == nil {
		plain = []byte{}
	}

	*b = EncryptedBytes(plain)

	return nil
}

func (b EncryptedBytes) Value() (driver.Value, error) {
	if b == nil {
		return nil, nil
	}
	return seal([]byte(b))
}
