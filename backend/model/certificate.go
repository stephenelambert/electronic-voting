package model

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CertificateRole string

const (
	CertificateGlobalAdminRole       CertificateRole = "global_admin"
	CertificateSystemRole            CertificateRole = "system"
	CertificateJurisdictionAdminRole CertificateRole = "jurisdiction_admin"
	CertificateRegistrarRole         CertificateRole = "registrar"
	CertificateVoterRole             CertificateRole = "voter"
)

type Certificate struct {
	ID                  string
	SerialNumber        string
	PubPEM              string
	CertPEM             string
	NotBefore           int64
	NotAfter            int64
	SignerCertID        *string
	JurisdictionID      *string
	Role                CertificateRole
	CRL                 *string
	CreationTimestamp   int64
	RevocationTimestamp *int64
	RevocationReason    *string
	// SignedRequestID is the signed request that authorized the certificate, like an admin's voter
	// authorization. It is nil for the root, and for global admins, which come from the server's
	// config.
	SignedRequestID *string
}

type nilCertificate struct {
	ID                  *string
	SerialNumber        *string
	PubPEM              *string
	CertPEM             *string
	NotBefore           *int64
	NotAfter            *int64
	SignerCertID        *string
	JurisdictionID      *string
	Role                *CertificateRole
	CRL                 *string
	CreationTimestamp   *int64
	RevocationTimestamp *int64
	RevocationReason    *string
	SignedRequestID     *string
}

type Certificates []Certificate

// AuthorizedCertificate is a certificate along with the signed request that authorized it, like an
// admin's voter authorization
type AuthorizedCertificate struct {
	Certificate   Certificate
	Authorization SignedRequest
}

type AuthorizedCertificates []AuthorizedCertificate

func (cert *Certificate) DbInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if cert.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		cert.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO certificates(id, serial_number, pub_pem, cert_pem, not_before, not_after, signer_cert_id, jurisdiction_id, role, crl, creation_timestamp, revocation_timestamp, revocation_reason, signed_request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);",
		cert.ID,
		cert.SerialNumber,
		cert.PubPEM,
		cert.CertPEM,
		cert.NotBefore,
		cert.NotAfter,
		cert.SignerCertID,
		cert.JurisdictionID,
		cert.Role,
		cert.CRL,
		cert.CreationTimestamp,
		cert.RevocationTimestamp,
		cert.RevocationReason,
		cert.SignedRequestID)

	if err != nil {
		log.Printf("error inserting certificate: %v", err)
		return
	}

	return
}

func (certs *Certificates) FindByRoleAndJurisdiction(ctx context.Context, tx pgx.Tx, role CertificateRole, jurisdictionID *string) (err error) {
	if certs == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT
			id,
			serial_number,
			pub_pem,
			cert_pem,
			not_before,
			not_after,
			signer_cert_id,
			jurisdiction_id,
			role,
			crl,
			creation_timestamp,
			revocation_timestamp,
			revocation_reason,
			signed_request_id
		FROM certificates
		WHERE role IS NOT DISTINCT FROM $1
			AND jurisdiction_id IS NOT DISTINCT FROM $2
			AND revocation_timestamp IS NULL;`,
		role,
		jurisdictionID)

	if err != nil {
		log.Printf("error querying for certificates by role and jurisdiction: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var cert Certificate

		err = rows.Scan(&cert.ID,
			&cert.SerialNumber,
			&cert.PubPEM,
			&cert.CertPEM,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.SignerCertID,
			&cert.JurisdictionID,
			&cert.Role,
			&cert.CRL,
			&cert.CreationTimestamp,
			&cert.RevocationTimestamp,
			&cert.RevocationReason,
			&cert.SignedRequestID)

		if err != nil {
			log.Printf("error scanning for certificate by role and jurisdiction: %v", err)
			return
		}

		*certs = append(*certs, cert)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for certs by role and jurisdiction: %v", err)
		return
	}

	return
}

func (certs *Certificates) FindActiveByPubPEM(ctx context.Context, tx pgx.Tx, pubPEM string) (err error) {
	if certs == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT
			id,
			serial_number,
			pub_pem,
			cert_pem,
			not_before,
			not_after,
			signer_cert_id,
			jurisdiction_id,
			role,
			crl,
			creation_timestamp,
			revocation_timestamp,
			revocation_reason,
			signed_request_id
		FROM
			certificates
		WHERE
			pub_pem = $1 AND
			revocation_timestamp IS NULL;`,
		pubPEM)

	if err != nil {
		log.Printf("error querying for certificates by public key: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var cert Certificate

		err = rows.Scan(&cert.ID,
			&cert.SerialNumber,
			&cert.PubPEM,
			&cert.CertPEM,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.SignerCertID,
			&cert.JurisdictionID,
			&cert.Role,
			&cert.CRL,
			&cert.CreationTimestamp,
			&cert.RevocationTimestamp,
			&cert.RevocationReason,
			&cert.SignedRequestID)

		if err != nil {
			log.Printf("error scanning for certificate by public key: %v", err)
			return
		}

		*certs = append(*certs, cert)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for active certs by key: %v", err)
		return
	}

	return
}

// FindByJurisdictionAndRole finds the jurisdiction's active certificates for the role that a signed
// request authorized, in the order they were issued, each with that request. Voter certificates are
// always authorized by one.
func (acs *AuthorizedCertificates) FindByJurisdictionAndRole(ctx context.Context, tx pgx.Tx, jurisdictionID string, role CertificateRole) (err error) {
	if acs == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT
			certificates.id,
			certificates.serial_number,
			certificates.pub_pem,
			certificates.cert_pem,
			certificates.not_before,
			certificates.not_after,
			certificates.signer_cert_id,
			certificates.jurisdiction_id,
			certificates.role,
			certificates.crl,
			certificates.creation_timestamp,
			certificates.revocation_timestamp,
			certificates.revocation_reason,
			certificates.signed_request_id,
			signed_requests.id,
			signed_requests.action,
			signed_requests.instance,
			signed_requests.role,
			signed_requests.jurisdiction_id,
			signed_requests.request_timestamp,
			signed_requests.body,
			signed_requests.public_key,
			signed_requests.signature,
			signed_requests.certificate_id,
			authorization_certificates.cert_pem
		FROM certificates
		INNER JOIN signed_requests
			ON signed_requests.id = certificates.signed_request_id
		LEFT JOIN certificates AS authorization_certificates
			ON authorization_certificates.id = signed_requests.certificate_id
		WHERE certificates.jurisdiction_id = $1
			AND certificates.role = $2
			AND certificates.revocation_timestamp IS NULL
		ORDER BY certificates.creation_timestamp, certificates.id;`,
		jurisdictionID,
		role)
	if err != nil {
		log.Printf("error querying for authorized certificates by jurisdiction and role: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var ac AuthorizedCertificate
		cert := &ac.Certificate

		err = rows.Scan(&cert.ID,
			&cert.SerialNumber,
			&cert.PubPEM,
			&cert.CertPEM,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.SignerCertID,
			&cert.JurisdictionID,
			&cert.Role,
			&cert.CRL,
			&cert.CreationTimestamp,
			&cert.RevocationTimestamp,
			&cert.RevocationReason,
			&cert.SignedRequestID,
			&ac.Authorization.ID,
			&ac.Authorization.Action,
			&ac.Authorization.Instance,
			&ac.Authorization.Role,
			&ac.Authorization.JurisdictionID,
			&ac.Authorization.RequestTimestamp,
			&ac.Authorization.Body,
			&ac.Authorization.PublicKey,
			&ac.Authorization.Signature,
			&ac.Authorization.CertificateID,
			&ac.Authorization.CertPEM)
		if err != nil {
			log.Printf("error scanning for authorized certificate by jurisdiction and role: %v", err)
			return
		}

		*acs = append(*acs, ac)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for authorized certs by jurisdiction and role: %v", err)
		return
	}

	return
}

func (c *nilCertificate) toCert() (cert *Certificate) {
	if c == nil {
		return
	}

	cert = &Certificate{}

	if c.ID != nil {
		cert.ID = *c.ID
	}
	if c.SerialNumber != nil {
		cert.SerialNumber = *c.SerialNumber
	}
	if c.PubPEM != nil {
		cert.PubPEM = *c.PubPEM
	}
	if c.CertPEM != nil {
		cert.CertPEM = *c.CertPEM
	}
	if c.NotBefore != nil {
		cert.NotBefore = *c.NotBefore
	}
	if c.NotAfter != nil {
		cert.NotAfter = *c.NotAfter
	}
	if c.SignerCertID != nil {
		cert.SignerCertID = c.SignerCertID
	}
	if c.JurisdictionID != nil {
		cert.JurisdictionID = c.JurisdictionID
	}
	if c.Role != nil {
		cert.Role = *c.Role
	}
	if c.CRL != nil {
		cert.CRL = c.CRL
	}
	if c.CreationTimestamp != nil {
		cert.CreationTimestamp = *c.CreationTimestamp
	}
	if c.RevocationTimestamp != nil {
		cert.RevocationTimestamp = c.RevocationTimestamp
	}
	if c.RevocationReason != nil {
		cert.RevocationReason = c.RevocationReason
	}
	if c.SignedRequestID != nil {
		cert.SignedRequestID = c.SignedRequestID
	}

	return
}
