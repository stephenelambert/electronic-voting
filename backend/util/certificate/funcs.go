package certificate

import (
	"context"
	"crypto/x509"
	"electronic-voting/localcrypto"
	"electronic-voting/localsigner"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/ptr"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertView is an object to represent certs as they are returned to clients
type CertView struct {
	CertPEM        string  `json:"cert_pem"`
	ID             string  `json:"id"`
	JurisdictionID *string `json:"jurisdiction_id,omitempty"`
	Role           string  `json:"role"`
}

// ModelCertToView converts a model Certificate object to an object to return
// to HTTP clients.
func ModelCertToView(cert model.Certificate) CertView {
	return CertView{
		CertPEM:        cert.CertPEM,
		ID:             cert.ID,
		JurisdictionID: cert.JurisdictionID,
		Role:           string(cert.Role),
	}
}

// SystemSignAndInsertCert uses the localsigner to sign a certificate with the given role (and
// jurisdiction, if required by the role) for the given public key. It then inserts the
// certificate into the database if successful. pubPEM must exactly match the public_key of a row in
// signing_keys. signedRequestID is the stored signed request that authorized the certificate, or nil
// if none did (like for global admins, which come from the server's config). The certificate is
// returned, as well as any error and an HTTP status code for any HTTP handler callers.
func SystemSignAndInsertCert(ctx context.Context, role model.CertificateRole, jurisdictionID *string, pubPEM string, signedRequestID *string) (modelCert *model.Certificate, status int, err error) {
	tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

	status = http.StatusOK

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		err = fmt.Errorf("error decoding %s public key PEM", role)
		status = http.StatusBadRequest
		return
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = fmt.Errorf("error parsing %s public key: %w", role, err)
		status = http.StatusBadRequest
		return
	}

	certTemplate, err := localcrypto.CreateCertificateTemplate(role, jurisdictionID)
	if err != nil {
		err = fmt.Errorf("error creating %s certificate template: %w", role, err)
		status = http.StatusInternalServerError
		return
	}

	certDER, err := localsigner.SignCertificate(ctx, certTemplate, publicKey)
	if err != nil {
		err = fmt.Errorf("error signing %s certificate: %w", role, err)
		status = http.StatusInternalServerError
		return
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		err = fmt.Errorf("error parsing signed %s certificate: %w", role, err)
		status = http.StatusInternalServerError
		return
	}

	pemBlock := pem.Block{
		Bytes: certDER,
		Type:  localcrypto.PEMStringCertificate,
	}
	certPEM := pem.EncodeToMemory(&pemBlock)

	modelCert = &model.Certificate{
		SerialNumber:      localcrypto.SerialNumberString(cert.SerialNumber),
		PubPEM:            pubPEM,
		CertPEM:           string(certPEM),
		NotBefore:         cert.NotBefore.Unix(),
		NotAfter:          cert.NotAfter.Unix(),
		SignerCertID:      ptr.Of(localsigner.GetCertID()),
		JurisdictionID:    jurisdictionID,
		Role:              role,
		CreationTimestamp: time.Now().Unix(),
		SignedRequestID:   signedRequestID,
	}

	err = modelCert.DbInsert(ctx, tx)
	if err != nil {
		err = fmt.Errorf("error inserting %s certificate: %w", role, err)
		status = http.StatusInternalServerError
		return
	}

	return
}
