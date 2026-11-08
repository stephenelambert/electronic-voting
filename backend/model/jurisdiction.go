package model

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Jurisdiction struct {
	ID               string
	Name             string
	Info             string
	CreatedTimestamp int64
	// SignedRequest is the admin's signed request that created the jurisdiction. Only DBInsert and
	// FindSignedRequest use it: other queries leave it empty.
	SignedRequest SignedRequest
}

type Jurisdictions []Jurisdiction

// DBInsert inserts the jurisdiction along with the signed request that created it
func (j *Jurisdiction) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if err = j.SignedRequest.DBInsert(ctx, tx); err != nil {
		return
	}

	if j.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		j.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO voting_jurisdictions(id, name, info, created_timestamp, signed_request_id) VALUES($1, $2, $3, $4, $5);",
		j.ID,
		j.Name,
		j.Info,
		j.CreatedTimestamp,
		j.SignedRequest.ID)
	return
}

func (j *Jurisdiction) FindById(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT name, info, created_timestamp
		FROM voting_jurisdictions
		WHERE id = $1;`,
		j.ID).Scan(&j.Name, &j.Info, &j.CreatedTimestamp)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for jurisdiction by id: %v", err)
		return
	}

	found = true

	return
}

// FindSignedRequest finds the signed request that created the jurisdiction, which must exist
func (j *Jurisdiction) FindSignedRequest(ctx context.Context, tx pgx.Tx) (err error) {
	err = tx.QueryRow(ctx,
		`SELECT
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
			certificates.cert_pem
		FROM voting_jurisdictions
		INNER JOIN signed_requests
			ON signed_requests.id = voting_jurisdictions.signed_request_id
		LEFT JOIN certificates
			ON certificates.id = signed_requests.certificate_id
		WHERE voting_jurisdictions.id = $1;`,
		j.ID).Scan(&j.SignedRequest.ID,
		&j.SignedRequest.Action,
		&j.SignedRequest.Instance,
		&j.SignedRequest.Role,
		&j.SignedRequest.JurisdictionID,
		&j.SignedRequest.RequestTimestamp,
		&j.SignedRequest.Body,
		&j.SignedRequest.PublicKey,
		&j.SignedRequest.Signature,
		&j.SignedRequest.CertificateID,
		&j.SignedRequest.CertPEM)
	if err != nil {
		log.Printf("error querying for signed request that created jurisdiction: %v", err)
	}

	return
}

func (js *Jurisdictions) FindAll(ctx context.Context, tx pgx.Tx) (err error) {
	if js == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT id, name, info, created_timestamp
		FROM voting_jurisdictions
		ORDER BY name;`)
	if err != nil {
		log.Printf("error querying in FindAll: %v\n", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var j Jurisdiction

		if err = rows.Scan(&j.ID, &j.Name, &j.Info, &j.CreatedTimestamp); err != nil {
			log.Printf("error scanning row in FindAll: %v\n", err)
			return
		}

		*js = append(*js, j)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for all jurisdictions: %v", err)
		return
	}

	return
}
