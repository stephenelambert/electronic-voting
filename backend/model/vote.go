package model

import (
	"context"
	"errors"
	"log"

	"electronic-voting/util/votecounts"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Vote is a vote cast in an election. It isn't tied to the voter, and deliberately has no
// timestamp, since when it arrived could link it to the voter's request for its signature.
type Vote struct {
	ID         string
	ElectionID string
	// Nonce is the 32 random bytes RFC 9474 adds to the front of the vote, as lowercase hex
	Nonce string
	// Raw is the vote JSON, exactly as signed
	Raw         string
	CandidateID string
	// Signature is the election key's signature over the nonce followed by Raw, as base64
	Signature string
	// TreePosition is the vote's position when the election's votes are sorted by nonce, starting
	// at 0. It's only set once the election's hash tree is built.
	TreePosition int64
}

func (v *Vote) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if v.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		v.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO votes(id, election_id, nonce, raw, candidate_id, signature) VALUES($1,$2,$3,$4,$5,$6);",
		v.ID,
		v.ElectionID,
		v.Nonce,
		v.Raw,
		v.CandidateID,
		v.Signature)
	if err != nil {
		log.Printf("error inserting vote: %v", err)
	}

	return
}

// FindByElectionAndNonce finds the vote in the election with the nonce
func (v *Vote) FindByElectionAndNonce(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT id, raw, candidate_id, signature
		FROM votes
		WHERE election_id = $1 AND nonce = $2;`,
		v.ElectionID,
		v.Nonce).Scan(&v.ID,
		&v.Raw,
		&v.CandidateID,
		&v.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for vote by nonce: %v", err)
		return
	}

	found = true

	return
}

// CountVotesByCandidate counts the election's votes for each candidate ID they name
func CountVotesByCandidate(ctx context.Context, tx pgx.Tx, electionID string) (counts votecounts.Counts, err error) {
	rows, err := tx.Query(ctx,
		`SELECT candidate_id, count(*)
		FROM votes
		WHERE election_id = $1
		GROUP BY candidate_id;`,
		electionID)
	if err != nil {
		log.Printf("error counting votes by candidate: %v", err)
		return
	}

	defer rows.Close()

	counts = votecounts.Counts{}
	for rows.Next() {
		var candidateID string
		var count int64

		if err = rows.Scan(&candidateID, &count); err != nil {
			log.Printf("error scanning for count of votes by candidate: %v", err)
			return
		}

		counts[candidateID] = uint64(count)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while counting votes by candidate: %v", err)
		return
	}

	return
}

// ListVotesByNonce lists the election's votes in nonce order. Only the votes' nonces, raw votes,
// candidate IDs and signatures are set.
func ListVotesByNonce(ctx context.Context, tx pgx.Tx, electionID string) (votes []Vote, err error) {
	rows, err := tx.Query(ctx,
		`SELECT nonce, raw, candidate_id, signature
		FROM votes
		WHERE election_id = $1
		ORDER BY nonce;`,
		electionID)
	if err != nil {
		log.Printf("error querying for votes: %v", err)
		return
	}

	defer rows.Close()

	votes = []Vote{}
	for rows.Next() {
		vote := Vote{
			ElectionID: electionID,
		}

		if err = rows.Scan(&vote.Nonce, &vote.Raw, &vote.CandidateID, &vote.Signature); err != nil {
			log.Printf("error scanning for vote: %v", err)
			return
		}

		votes = append(votes, vote)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while querying for votes: %v", err)
		return
	}

	return
}

// SetTreePositions sets the position of each of the election's votes in nonce order, starting at
// 0, which is their order in its hash tree. It returns how many votes were given a position.
func SetTreePositions(ctx context.Context, tx pgx.Tx, electionID string) (positioned int64, err error) {
	tag, err := tx.Exec(ctx,
		`UPDATE votes
		SET tree_position = ranked.position
		FROM (
			SELECT id, row_number() OVER (ORDER BY nonce) - 1 AS position
			FROM votes
			WHERE election_id = $1
		) ranked
		WHERE votes.id = ranked.id;`,
		electionID)
	if err != nil {
		log.Printf("error setting tree positions of votes: %v", err)
		return
	}

	positioned = tag.RowsAffected()

	return
}

// FindLeafByElectionAndNonce finds the vote in the election with the nonce, once the election's
// hash tree is built. Only the vote's raw vote, signature and tree position are set.
func (v *Vote) FindLeafByElectionAndNonce(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT raw, signature, tree_position
		FROM votes
		WHERE election_id = $1 AND nonce = $2;`,
		v.ElectionID,
		v.Nonce).Scan(&v.Raw,
		&v.Signature,
		&v.TreePosition)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for vote's leaf by nonce: %v", err)
		return
	}

	found = true

	return
}

// FindNeighborsOfNonce finds the election's votes just before and after the nonce in nonce order,
// once the election's hash tree is built, leaving out either if there isn't one. Only the votes'
// nonces, raw votes, signatures and tree positions are set, and they are in nonce order.
func FindNeighborsOfNonce(ctx context.Context, tx pgx.Tx, electionID, nonce string) (votes []Vote, err error) {
	// the nonce comparisons use the column's C collation, so they're in byte order, like the tree
	rows, err := tx.Query(ctx,
		`(SELECT nonce, raw, signature, tree_position
		FROM votes
		WHERE election_id = $1 AND nonce < $2
		ORDER BY nonce DESC
		LIMIT 1)
		UNION ALL
		(SELECT nonce, raw, signature, tree_position
		FROM votes
		WHERE election_id = $1 AND nonce > $2
		ORDER BY nonce
		LIMIT 1)
		ORDER BY nonce;`,
		electionID,
		nonce)
	if err != nil {
		log.Printf("error querying for neighbors of nonce: %v", err)
		return
	}

	defer rows.Close()

	votes = []Vote{}
	for rows.Next() {
		vote := Vote{
			ElectionID: electionID,
		}

		if err = rows.Scan(&vote.Nonce, &vote.Raw, &vote.Signature, &vote.TreePosition); err != nil {
			log.Printf("error scanning for neighbor of nonce: %v", err)
			return
		}

		votes = append(votes, vote)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while querying for neighbors of nonce: %v", err)
		return
	}

	return
}
