package localcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"electronic-voting/model"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// latestTime is the latest time that can be used in a certificate.
var latestTime = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

// CreateCertificateTemplate creates a certificate template for signing elsewhere in the system
func CreateCertificateTemplate(role model.CertificateRole, jurisdictionID *string) (template *x509.Certificate, err error) {
	var (
		isCA       bool
		commonName string
		keyUsage   x509.KeyUsage
	)

	switch role {
	case model.CertificateSystemRole:
		isCA = true
		commonName = "system"

		// system key is the single root that signs (and revokes) every other cert
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case model.CertificateGlobalAdminRole:
		commonName = "admin.global"

		// global admin key will be used to sign requests from admin users, including
		// requests authorizing the system to sign and revoke other certs
		keyUsage = x509.KeyUsageDigitalSignature
	case model.CertificateJurisdictionAdminRole:
		if jurisdictionID == nil || !UUIDIsValid(*jurisdictionID) {
			err = errors.New("jurisdiction id must be valid uuid for jurisdiction admin cert")
			return
		}
		commonName = strings.Join([]string{"admin", *jurisdictionID, "jurisdiction"}, ".")

		// jurisdiction admin key will be used to sign requests from jurisdiction admin users,
		// including requests authorizing certs for other jurisdiction admins, registrars, and
		// voters in the jurisdiction and child jurisdictions
		keyUsage = x509.KeyUsageDigitalSignature
	case model.CertificateRegistrarRole:
		if jurisdictionID == nil || !UUIDIsValid(*jurisdictionID) {
			err = errors.New("jurisdiction id must be valid uuid for jurisdiction registrar cert")
			return
		}
		commonName = strings.Join([]string{"registrar", *jurisdictionID, "jurisdiction"}, ".")

		// jurisdiction registrar key will be used to sign requests from jurisdiction registrar
		// users, including requests authorizing certs for voters in the jurisdiction and child
		// jurisdictions
		keyUsage = x509.KeyUsageDigitalSignature
	case model.CertificateVoterRole:
		if jurisdictionID == nil || !UUIDIsValid(*jurisdictionID) {
			err = errors.New("jurisdiction id must be valid uuid for jurisdiction voter cert")
			return
		}
		commonName = strings.Join([]string{"voter", *jurisdictionID, "jurisdiction"}, ".")

		// jurisdiction voter key will be used to sign requests from jurisdiction voter
		keyUsage = x509.KeyUsageDigitalSignature
	}

	// the trust tree is flat: only the system root is a CA, and a max path length of 0
	// prevents it from having any intermediate CAs beneath it. SerialNumber is left nil so
	// x509.CreateCertificate generates a random serial that conforms to RFC 5280.
	template = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            0,
		MaxPathLenZero:        isCA,
		NotBefore:             time.Now(),
		NotAfter:              latestTime,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		KeyUsage: keyUsage,
	}

	return
}

// SerialNumberString formats a certificate serial number the way it is stored in the database:
// lowercase hex without leading zeros, so each serial has exactly one stored form
func SerialNumberString(serial *big.Int) string {
	return serial.Text(16)
}

// NormalizePublicKeyPEM parses a PEM-encoded public key and re-encodes it, so the same key
// always has the same PEM text when stored in or looked up from the database. The parsed
// public key is also returned so callers don't need to parse it again.
func NormalizePublicKeyPEM(pubPEM string) (normalized string, publicKey any, err error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		err = errors.New("public key is not valid PEM")
		return
	}

	publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = fmt.Errorf("error parsing public key: %w", err)
		return
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		err = fmt.Errorf("error marshaling public key: %w", err)
		return
	}

	normalized = string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMStringPublicKey,
		Bytes: publicKeyDER,
	}))

	return
}

// ParseAccountPublicKey normalizes an account's public key (see NormalizePublicKeyPEM) and returns
// it parsed. Accounts sign requests with ECDSA P-384 keys.
func ParseAccountPublicKey(pubPEM string) (normalized string, publicKey *ecdsa.PublicKey, err error) {
	normalized, parsed, err := NormalizePublicKeyPEM(pubPEM)
	if err != nil {
		return
	}

	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P384() {
		normalized, publicKey = "", nil
		err = errors.New("public key is not an ECDSA P-384 key")
		return
	}

	return
}

// electionKeyBits is the size of the RSA keys generated for elections
const electionKeyBits = 2048

// ElectionKeyVariant is the RSA blind signature variant (RFC 9474) that election keys are used
// with. Requests to create elections must state it, so the signed request records the key's only
// use.
const ElectionKeyVariant = "RSABSSA-SHA384-PSS-Randomized"

// GenerateElectionKey generates a key pair for an election, returning the private key as PKCS #8
// PEM and the public key as PKIX PEM (in the same form NormalizePublicKeyPEM produces). Election
// keys are RSA because votes will be signed with RSA blind signatures (RFC 9474).
func GenerateElectionKey() (privateKeyPEM string, publicKeyPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, electionKeyBits)
	if err != nil {
		err = fmt.Errorf("error generating rsa key: %w", err)
		return
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		err = fmt.Errorf("error marshaling private key: %w", err)
		return
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		err = fmt.Errorf("error marshaling public key: %w", err)
		return
	}

	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMStringPrivateKey,
		Bytes: privateKeyDER,
	}))
	publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMStringPublicKey,
		Bytes: publicKeyDER,
	}))

	return
}

func UUIDIsValid(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// UUIDIsCanonical reports whether uuidStr is a UUID in canonical form (lowercase and hyphenated,
// as crypto.randomUUID() generates). Clients generate IDs inside the requests they sign, and
// requiring this form keeps each signed ID identical to the stored one.
func UUIDIsCanonical(uuidStr string) bool {
	uid, err := uuid.Parse(uuidStr)
	return err == nil && uid.String() == uuidStr
}
