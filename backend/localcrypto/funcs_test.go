package localcrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// testPublicKeyPEM returns a public key as PEM, the way NormalizePublicKeyPEM lays it out
func testPublicKeyPEM(t *testing.T, publicKey any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("error encoding public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: PEMStringPublicKey, Bytes: der}))
}

func TestParseAccountPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}
	normalized := testPublicKeyPEM(t, &key.PublicKey)

	// browsers export keys on one line, which normalizing lays out like Go does
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	oneLine := "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END PUBLIC KEY-----"
	got, publicKey, err := ParseAccountPublicKey(oneLine)
	if err != nil {
		t.Fatalf("P-384 key was rejected: %v", err)
	}
	if got != normalized {
		t.Errorf("key normalized to\n%s\nwant\n%s", got, normalized)
	}
	if !publicKey.Equal(&key.PublicKey) {
		t.Error("parsed key isn't the key")
	}

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating RSA key: %v", err)
	}
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	invalid := map[string]string{
		"P-256":   testPublicKeyPEM(t, &p256.PublicKey),
		"P-521":   testPublicKeyPEM(t, &p521.PublicKey),
		"RSA":     testPublicKeyPEM(t, &rsaKey.PublicKey),
		"Ed25519": testPublicKeyPEM(t, ed25519Key),
		"not PEM": "not a key",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseAccountPublicKey(value); err == nil {
				t.Errorf("%s key was accepted", name)
			}
		})
	}
}
