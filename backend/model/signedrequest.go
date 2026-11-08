package model

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SignedRequest is an authenticated request, stored exactly as it was signed so its signature can be
// checked again later (see localcrypto.RequestSignedData). Whether it is published depends on what
// references it.
type SignedRequest struct {
	ID string
	// Action names what the request does, like "voter.authorize"
	Action string
	// Instance is the instance the request was signed for: the base64 SHA-256 hash of the public key
	// of its root certificate
	Instance string
	// Role and JurisdictionID are the role and jurisdiction of the certificate the signer acted
	// under, if the request needed one. JurisdictionID is nil for roles without one.
	Role           *CertificateRole
	JurisdictionID *string
	// RequestTimestamp is the timestamp from the Authorization header, kept as the string the
	// signature covers
	RequestTimestamp string
	Body             string
	// PublicKey is the PEM of the key that signed the request
	PublicKey string
	// Signature is base64
	Signature string
	// CertificateID is the certificate that Role and JurisdictionID name, if the request needed one
	CertificateID *string
	// CertPEM is the PEM of that certificate, so the signer can be checked. It isn't stored with the
	// request: queries join it from certificates.
	CertPEM *string
}

func (sr *SignedRequest) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if sr.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		sr.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO signed_requests(id, action, instance, role, jurisdiction_id, request_timestamp, body, public_key, signature, certificate_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);",
		sr.ID,
		sr.Action,
		sr.Instance,
		sr.Role,
		sr.JurisdictionID,
		sr.RequestTimestamp,
		sr.Body,
		sr.PublicKey,
		sr.Signature,
		sr.CertificateID)
	if err != nil {
		log.Printf("error inserting signed request: %v", err)
	}

	return
}
