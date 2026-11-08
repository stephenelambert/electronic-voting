package localsigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/dbcrypt"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// privateKey is the private signing key used by the system
var privateKey *ecdsa.PrivateKey

// signingCert is the X.509 certificate used for signing by the system
var signingCert *x509.Certificate

// modelCert is the certificate in a form that is stored in the database
var modelCert *model.Certificate

// instance identifies this instance in the requests signed for it: the base64 SHA-256 hash of the
// system certificate's public key
var instance string

// Init fetches the private key and certificate from the database and initializes them.
// If not present, they are created and added to the database.
func Init(ctx context.Context) (err error) {
	if err = loadOrCreate(ctx); err != nil {
		return
	}

	// every instance has its own root, so its key identifies the instance
	instance, err = localcrypto.PublicKeyHash(modelCert.PubPEM)
	if err != nil {
		err = fmt.Errorf("error hashing system signing public key: %w", err)
	}

	return
}

// loadOrCreate fetches the private key and certificate from the database, creating them and adding
// them to the database if they aren't there
func loadOrCreate(ctx context.Context) (err error) {
	tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

	certs := (model.Certificates)([]model.Certificate{})
	err = certs.FindByRoleAndJurisdiction(ctx, tx, model.CertificateSystemRole, nil)
	if err != nil {
		err = fmt.Errorf("error querying for system signer certs: %w", err)
		return
	}

	if len(certs) != 0 {
		modelCert = &certs[0]

		signingKey := model.SigningKey{
			PublicKey: modelCert.PubPEM,
		}
		var found bool
		found, err = signingKey.FindByPublicKey(ctx, tx)
		if err != nil {
			err = fmt.Errorf("error querying local system signer key: %w", err)
			return
		}
		if !found {
			err = errors.New("system signing key not found even though system signing cert was")
			return
		}

		pemBlock, _ := pem.Decode(([]byte)(modelCert.CertPEM))
		signingCert, err = x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			err = fmt.Errorf("error parsing system signing cert: %w", err)
			return
		}

		pemBlock, _ = pem.Decode(([]byte)(signingKey.PrivateKey))
		if pemBlock.Type == localcrypto.PEMStringECPrivateKey {
			privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
			if err != nil {
				err = fmt.Errorf("error parsing system signing key: %w", err)
				return
			}
		} else {
			err = errors.New("system signer configured with unsupported private key type")
			return
		}

		// confirm that the key matches the cert
		pubKey := signingCert.PublicKey.(interface {
			Equal(crypto.PublicKey) bool
		})
		if !pubKey.Equal(&privateKey.PublicKey) {
			err = errors.New("system signing key does not match system signing certificate")
			return
		}

		// all good, return
		return
	}

	// no certificate or key, create them
	privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("error generating private key for system signer: %w", err)
		return
	}

	// generate certificate
	template, err := localcrypto.CreateCertificateTemplate(model.CertificateSystemRole, nil)
	if err != nil {
		err = fmt.Errorf("error creating template for system signer certificate: %v", err)
		return
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		err = fmt.Errorf("error generating system signing certificate: %w", err)
		return
	}

	signingCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		err = fmt.Errorf("error parsing new system signing certificate: %w", err)
		return
	}

	pemBlock := pem.Block{
		Bytes: certDER,
		Type:  localcrypto.PEMStringCertificate,
	}
	certPEM := pem.EncodeToMemory(&pemBlock)

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		err = fmt.Errorf("error marshaling system signing private key: %w", err)
		return
	}
	pemBlock = pem.Block{
		Type:  localcrypto.PEMStringECPrivateKey,
		Bytes: privateKeyDER,
	}
	privateKeyPEM := pem.EncodeToMemory(&pemBlock)

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		err = fmt.Errorf("error marshaling system signing public key: %w", err)
		return
	}
	pemBlock = pem.Block{
		Type:  localcrypto.PEMStringPublicKey,
		Bytes: publicKeyDER,
	}
	publicKeyPEM := pem.EncodeToMemory(&pemBlock)

	now := time.Now().Unix()
	signingKey := &model.SigningKey{
		PrivateKey:        dbcrypt.EncryptedString(privateKeyPEM),
		PublicKey:         string(publicKeyPEM),
		OwnerType:         model.KeySystemOwner,
		CreationTimestamp: now,
	}

	err = signingKey.DbInsert(ctx, tx)
	if err != nil {
		err = fmt.Errorf("error inserting signing key for system signer: %w", err)
		return
	}

	modelCert = &model.Certificate{
		SerialNumber:      localcrypto.SerialNumberString(signingCert.SerialNumber),
		PubPEM:            signingKey.PublicKey,
		CertPEM:           string(certPEM),
		NotBefore:         signingCert.NotBefore.Unix(),
		NotAfter:          signingCert.NotAfter.Unix(),
		Role:              model.CertificateSystemRole,
		CreationTimestamp: now,
	}

	err = modelCert.DbInsert(ctx, tx)
	if err != nil {
		err = fmt.Errorf("error inserting certificate for system signer: %w", err)
		return
	}

	return
}

// GetCertID returns the ID of the system certificate in the database.
// Must not be called before Init().
func GetCertID() string {
	return modelCert.ID
}

// GetCert returns the system certificate, which is the root that signs every other certificate.
// Must not be called before Init().
func GetCert() model.Certificate {
	return *modelCert
}

// Instance returns the ID of this instance, which authenticated requests sign so they can't be used on
// another instance: the base64 SHA-256 hash of the DER encoding of the system certificate's public
// key. Must not be called before Init().
func Instance() string {
	return instance
}

// SignCertificate signs the input certificate with the system signing key (certificate)
// and returns the signed certificate as the DER bytes.
// certToSign should be created with localcrypto.CreateCertificateTemplate().
// This should not be called before Init()
func SignCertificate(ctx context.Context, certToSign *x509.Certificate, pub any) (signedCert []byte, err error) {
	signedCert, err = x509.CreateCertificate(rand.Reader, certToSign, signingCert, pub, privateKey)
	if err != nil {
		err = fmt.Errorf("error generating system signing certificate: %w", err)
		return
	}

	return
}
