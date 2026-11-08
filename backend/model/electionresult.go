package model

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ElectionResult is an election's published results: the admin's signed request publishing the root
// of the election's hash tree and its tally, which is published for auditing. It is written along
// with the hash tree and never changes.
type ElectionResult struct {
	ID         string
	ElectionID string
	// VoteCount is the number of votes in the election. The root of its hash tree is the node with
	// first_leaf 0 and this leaf_count.
	VoteCount        int64
	SignedRequest    SignedRequest
	CreatedTimestamp int64
}

// DBInsert inserts the result along with the signed request that published it
func (er *ElectionResult) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if err = er.SignedRequest.DBInsert(ctx, tx); err != nil {
		return
	}

	if er.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		er.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO election_results(id, election_id, vote_count, signed_request_id, created_timestamp) VALUES($1,$2,$3,$4,$5);",
		er.ID,
		er.ElectionID,
		er.VoteCount,
		er.SignedRequest.ID,
		er.CreatedTimestamp)
	if err != nil {
		log.Printf("error inserting election result: %v", err)
	}

	return
}

// FindByElection finds the election's result, along with the signed request that published it
func (er *ElectionResult) FindByElection(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT
			election_results.id,
			election_results.vote_count,
			election_results.created_timestamp,
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
		FROM election_results
		INNER JOIN signed_requests
			ON signed_requests.id = election_results.signed_request_id
		LEFT JOIN certificates
			ON certificates.id = signed_requests.certificate_id
		WHERE election_results.election_id = $1;`,
		er.ElectionID).Scan(&er.ID,
		&er.VoteCount,
		&er.CreatedTimestamp,
		&er.SignedRequest.ID,
		&er.SignedRequest.Action,
		&er.SignedRequest.Instance,
		&er.SignedRequest.Role,
		&er.SignedRequest.JurisdictionID,
		&er.SignedRequest.RequestTimestamp,
		&er.SignedRequest.Body,
		&er.SignedRequest.PublicKey,
		&er.SignedRequest.Signature,
		&er.SignedRequest.CertificateID,
		&er.SignedRequest.CertPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for election result: %v", err)
		return
	}

	found = true

	return
}
