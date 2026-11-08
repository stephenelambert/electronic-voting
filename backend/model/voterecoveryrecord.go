package model

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// VoteRecoveryRecord holds what a voter's client needs to finish casting its vote, or find it, from
// any device. The client encrypts the record, and it is stored as the body of the signed request
// that uploaded it, which is only returned to the voter.
type VoteRecoveryRecord struct {
	ID               string
	ElectionID       string
	AccountID        string
	SignedRequest    SignedRequest
	CreatedTimestamp int64
}

// DBInsert inserts the record along with the signed request that uploaded it
func (vrr *VoteRecoveryRecord) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if err = vrr.SignedRequest.DBInsert(ctx, tx); err != nil {
		return
	}

	if vrr.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		vrr.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO vote_recovery_records(id, election_id, account_id, signed_request_id, created_timestamp) VALUES($1,$2,$3,$4,$5);",
		vrr.ID,
		vrr.ElectionID,
		vrr.AccountID,
		vrr.SignedRequest.ID,
		vrr.CreatedTimestamp)
	if err != nil {
		log.Printf("error inserting vote recovery record: %v", err)
	}

	return
}

// FindByElectionAndAccount finds the account's record for the election, along with the signed
// request that uploaded it
func (vrr *VoteRecoveryRecord) FindByElectionAndAccount(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT
			vote_recovery_records.id,
			vote_recovery_records.created_timestamp,
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
		FROM vote_recovery_records
		INNER JOIN signed_requests
			ON signed_requests.id = vote_recovery_records.signed_request_id
		LEFT JOIN certificates
			ON certificates.id = signed_requests.certificate_id
		WHERE vote_recovery_records.election_id = $1
			AND vote_recovery_records.account_id = $2;`,
		vrr.ElectionID,
		vrr.AccountID).Scan(&vrr.ID,
		&vrr.CreatedTimestamp,
		&vrr.SignedRequest.ID,
		&vrr.SignedRequest.Action,
		&vrr.SignedRequest.Instance,
		&vrr.SignedRequest.Role,
		&vrr.SignedRequest.JurisdictionID,
		&vrr.SignedRequest.RequestTimestamp,
		&vrr.SignedRequest.Body,
		&vrr.SignedRequest.PublicKey,
		&vrr.SignedRequest.Signature,
		&vrr.SignedRequest.CertificateID,
		&vrr.SignedRequest.CertPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for vote recovery record: %v", err)
		return
	}

	found = true

	return
}
