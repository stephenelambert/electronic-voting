package dbcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// Init reads the key from the environment. It must be called before any encrypted column is read or
// written.
func Init() (err error) {
	genCommand := "generate with: openssl rand -base64 32"

	keyStr := os.Getenv(KeyEnvVar)
	if keyStr == "" {
		err = fmt.Errorf("database encryption key missing, %s must be set; %s", KeyEnvVar, genCommand)
		return
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("%s isn't valid base64 (%w); %s", KeyEnvVar, err, genCommand)
	}

	if len(keyBytes) != keyLength {
		return fmt.Errorf("%s must decode to %d bytes, not %d; %s", KeyEnvVar, keyLength, len(keyBytes), genCommand)
	}

	cipherBlock, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creating cipher block: %w", err)
	}

	aesKey, err = cipher.NewGCMWithRandomNonce(cipherBlock)
	if err != nil {
		return fmt.Errorf("error creating aead for database encryption: %w", err)
	}

	return
}

// open decrypts a value scanned from the database
func open(src any) ([]byte, error) {
	if aesKey == nil {
		return nil, errors.New("can't decrypt, since dbcrypt.Init hasn't been called")
	}

	if src == nil {
		return nil, errors.New("encrypted value is NULL")
	}

	bytesSrc, ok := src.([]byte)
	if !ok {
		return nil, fmt.Errorf("encrypted value must be bytes, got %T", src)
	}

	if len(bytesSrc) == 0 || bytesSrc[0] != version {
		return nil, errors.New("encrypted value has an unknown version")
	}

	// trim off version byte
	plain, err := aesKey.Open(nil, nil, bytesSrc[1:], nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting value, which may mean %s isn't the key it was encrypted with: %w", KeyEnvVar, err)
	}

	return plain, nil
}

// seal encrypts a value to be stored in the database
func seal(plain []byte) ([]byte, error) {
	if aesKey == nil {
		return nil, errors.New("can't encrypt, since dbcrypt.Init hasn't been called")
	}

	cipherText := aesKey.Seal(nil, nil, plain, nil)
	return append([]byte{version}, cipherText...), nil
}
