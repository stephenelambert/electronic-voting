package model

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

type Election struct {
	ID             string
	JurisdictionID string
	Title          string
	Description    string
	TimeOpen       int64
	TimeClose      int64
	// PublicKey is the public key of the election's signing key, which is how the election
	// references the key
	PublicKey        string
	CreatedTimestamp int64
	// Candidates are in ballot order
	Candidates []Candidate
	// SignedRequest is the admin's signed request that created the election, which certifies its key.
	// Only DBInsert and FindSignedRequest use it: other queries leave it empty.
	SignedRequest SignedRequest
}

type Elections []Election

type Candidate struct {
	ID          string
	ElectionID  string
	Position    int
	Name        string
	Description string
}

// DBInsert inserts the election and its candidates, along with the signed request that created it.
// Unlike most objects, IDs aren't generated here: clients generate them, so the requests they sign
// cover them.
func (e *Election) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if err = e.SignedRequest.DBInsert(ctx, tx); err != nil {
		return
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO elections(id, jurisdiction_id, title, description, time_open, time_close, public_key, created_timestamp, signed_request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);",
		e.ID,
		e.JurisdictionID,
		e.Title,
		e.Description,
		e.TimeOpen,
		e.TimeClose,
		e.PublicKey,
		e.CreatedTimestamp,
		e.SignedRequest.ID)
	if err != nil {
		log.Printf("error inserting election: %v", err)
		return
	}

	for i := range e.Candidates {
		candidate := &e.Candidates[i]
		candidate.ElectionID = e.ID

		_, err = tx.Exec(ctx,
			"INSERT INTO candidates(id, election_id, position, name, description) VALUES($1,$2,$3,$4,$5);",
			candidate.ID,
			candidate.ElectionID,
			candidate.Position,
			candidate.Name,
			candidate.Description)
		if err != nil {
			log.Printf("error inserting candidate: %v", err)
			return
		}
	}

	// casting a vote increments the election's counter, so it needs one from the start
	counter := ElectionVoteCounter{
		ElectionID: e.ID,
	}
	err = counter.DBInsert(ctx, tx)

	return
}

// FindByID finds the election with the ID, along with its candidates in ballot order
func (e *Election) FindByID(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	// the id is read back so it is always in canonical form, whatever form the caller used
	err = tx.QueryRow(ctx,
		`SELECT
			id,
			jurisdiction_id,
			title,
			description,
			time_open,
			time_close,
			public_key,
			created_timestamp
		FROM elections
		WHERE id = $1;`,
		e.ID).Scan(&e.ID,
		&e.JurisdictionID,
		&e.Title,
		&e.Description,
		&e.TimeOpen,
		&e.TimeClose,
		&e.PublicKey,
		&e.CreatedTimestamp)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for election by id: %v", err)
		return
	}

	found = true

	rows, err := tx.Query(ctx,
		`SELECT id, election_id, position, name, description
		FROM candidates
		WHERE election_id = $1
		ORDER BY position;`,
		e.ID)
	if err != nil {
		log.Printf("error querying for candidates of election: %v", err)
		return
	}

	defer rows.Close()

	e.Candidates = []Candidate{}
	for rows.Next() {
		var candidate Candidate

		err = rows.Scan(&candidate.ID,
			&candidate.ElectionID,
			&candidate.Position,
			&candidate.Name,
			&candidate.Description)
		if err != nil {
			log.Printf("error scanning for candidate of election: %v", err)
			return
		}

		e.Candidates = append(e.Candidates, candidate)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for candidates of election: %v", err)
		return
	}

	return
}

// FindSignedRequest finds the signed request that created the election, which must exist
func (e *Election) FindSignedRequest(ctx context.Context, tx pgx.Tx) (err error) {
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
		FROM elections
		INNER JOIN signed_requests
			ON signed_requests.id = elections.signed_request_id
		LEFT JOIN certificates
			ON certificates.id = signed_requests.certificate_id
		WHERE elections.id = $1;`,
		e.ID).Scan(&e.SignedRequest.ID,
		&e.SignedRequest.Action,
		&e.SignedRequest.Instance,
		&e.SignedRequest.Role,
		&e.SignedRequest.JurisdictionID,
		&e.SignedRequest.RequestTimestamp,
		&e.SignedRequest.Body,
		&e.SignedRequest.PublicKey,
		&e.SignedRequest.Signature,
		&e.SignedRequest.CertificateID,
		&e.SignedRequest.CertPEM)
	if err != nil {
		log.Printf("error querying for signed request that created election: %v", err)
	}

	return
}

// FindByJurisdiction finds the elections for the jurisdiction, most recent first. Only the ID,
// title, and opening and closing times are populated.
func (es *Elections) FindByJurisdiction(ctx context.Context, tx pgx.Tx, jurisdictionID string) (err error) {
	if es == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT id, title, time_open, time_close
		FROM elections
		WHERE jurisdiction_id = $1
		ORDER BY time_open DESC, id;`,
		jurisdictionID)
	if err != nil {
		log.Printf("error querying for elections by jurisdiction: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var e Election

		if err = rows.Scan(&e.ID, &e.Title, &e.TimeOpen, &e.TimeClose); err != nil {
			log.Printf("error scanning for election by jurisdiction: %v", err)
			return
		}

		*es = append(*es, e)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for elections by jurisdiction: %v", err)
		return
	}

	return
}
