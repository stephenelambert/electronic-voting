package model

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BlindSignedVote is a vote the election key signed blind, along with the voter's signed request
// for the signature, which is published for auditing
type BlindSignedVote struct {
	ID         string
	ElectionID string
	AccountID  string
	// BlindedMessage is base64
	BlindedMessage string
	SignedRequest  SignedRequest
	// BlindSignature is base64
	BlindSignature   string
	CreatedTimestamp int64
	// Authorization is the admin's signed request that authorized the voter certificate SignedRequest
	// was signed under. Only FindByElection loads it.
	Authorization SignedRequest
}

type BlindSignedVotes []BlindSignedVote

// DBInsert inserts the blind signed vote along with the signed request for it
func (bsv *BlindSignedVote) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if err = bsv.SignedRequest.DBInsert(ctx, tx); err != nil {
		return
	}

	if bsv.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		bsv.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO blinded_signed_votes(id, election_id, account_id, blinded_message, signed_request_id, blind_signature, created_timestamp) VALUES($1,$2,$3,$4,$5,$6,$7);",
		bsv.ID,
		bsv.ElectionID,
		bsv.AccountID,
		bsv.BlindedMessage,
		bsv.SignedRequest.ID,
		bsv.BlindSignature,
		bsv.CreatedTimestamp)
	if err != nil {
		log.Printf("error inserting blind signed vote: %v", err)
	}

	return
}

// FindByElectionAndAccount finds the vote signed for the account in the election, along with the
// signed request for it
func (bsv *BlindSignedVote) FindByElectionAndAccount(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT
			blinded_signed_votes.id,
			blinded_signed_votes.blinded_message,
			blinded_signed_votes.blind_signature,
			blinded_signed_votes.created_timestamp,
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
		FROM blinded_signed_votes
		INNER JOIN signed_requests
			ON signed_requests.id = blinded_signed_votes.signed_request_id
		LEFT JOIN certificates
			ON certificates.id = signed_requests.certificate_id
		WHERE blinded_signed_votes.election_id = $1
			AND blinded_signed_votes.account_id = $2;`,
		bsv.ElectionID,
		bsv.AccountID).Scan(&bsv.ID,
		&bsv.BlindedMessage,
		&bsv.BlindSignature,
		&bsv.CreatedTimestamp,
		&bsv.SignedRequest.ID,
		&bsv.SignedRequest.Action,
		&bsv.SignedRequest.Instance,
		&bsv.SignedRequest.Role,
		&bsv.SignedRequest.JurisdictionID,
		&bsv.SignedRequest.RequestTimestamp,
		&bsv.SignedRequest.Body,
		&bsv.SignedRequest.PublicKey,
		&bsv.SignedRequest.Signature,
		&bsv.SignedRequest.CertificateID,
		&bsv.SignedRequest.CertPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for blind signed vote: %v", err)
		return
	}

	found = true

	return
}

// FindByElection finds every vote signed in the election, in the order they were signed, each with
// the voter's signed request for the signature and the admin's signed request that authorized the
// voter. Requests for blind signatures need a voter certificate, and every voter certificate is
// authorized by a signed request, so no vote is left out.
func (bsvs *BlindSignedVotes) FindByElection(ctx context.Context, tx pgx.Tx, electionID string) (err error) {
	if bsvs == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT
			blinded_signed_votes.id,
			blinded_signed_votes.election_id,
			blinded_signed_votes.account_id,
			blinded_signed_votes.blinded_message,
			blinded_signed_votes.blind_signature,
			blinded_signed_votes.created_timestamp,
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
			voter_certificates.cert_pem,
			authorizations.id,
			authorizations.action,
			authorizations.instance,
			authorizations.role,
			authorizations.jurisdiction_id,
			authorizations.request_timestamp,
			authorizations.body,
			authorizations.public_key,
			authorizations.signature,
			authorizations.certificate_id,
			authorization_certificates.cert_pem
		FROM blinded_signed_votes
		INNER JOIN signed_requests
			ON signed_requests.id = blinded_signed_votes.signed_request_id
		INNER JOIN certificates AS voter_certificates
			ON voter_certificates.id = signed_requests.certificate_id
		INNER JOIN signed_requests AS authorizations
			ON authorizations.id = voter_certificates.signed_request_id
		LEFT JOIN certificates AS authorization_certificates
			ON authorization_certificates.id = authorizations.certificate_id
		WHERE blinded_signed_votes.election_id = $1
		ORDER BY blinded_signed_votes.created_timestamp, blinded_signed_votes.id;`,
		electionID)
	if err != nil {
		log.Printf("error querying for blind signed votes by election: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var bsv BlindSignedVote

		err = rows.Scan(&bsv.ID,
			&bsv.ElectionID,
			&bsv.AccountID,
			&bsv.BlindedMessage,
			&bsv.BlindSignature,
			&bsv.CreatedTimestamp,
			&bsv.SignedRequest.ID,
			&bsv.SignedRequest.Action,
			&bsv.SignedRequest.Instance,
			&bsv.SignedRequest.Role,
			&bsv.SignedRequest.JurisdictionID,
			&bsv.SignedRequest.RequestTimestamp,
			&bsv.SignedRequest.Body,
			&bsv.SignedRequest.PublicKey,
			&bsv.SignedRequest.Signature,
			&bsv.SignedRequest.CertificateID,
			&bsv.SignedRequest.CertPEM,
			&bsv.Authorization.ID,
			&bsv.Authorization.Action,
			&bsv.Authorization.Instance,
			&bsv.Authorization.Role,
			&bsv.Authorization.JurisdictionID,
			&bsv.Authorization.RequestTimestamp,
			&bsv.Authorization.Body,
			&bsv.Authorization.PublicKey,
			&bsv.Authorization.Signature,
			&bsv.Authorization.CertificateID,
			&bsv.Authorization.CertPEM)
		if err != nil {
			log.Printf("error scanning for blind signed vote by election: %v", err)
			return
		}

		*bsvs = append(*bsvs, bsv)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for blind signed votes by election: %v", err)
		return
	}

	return
}
