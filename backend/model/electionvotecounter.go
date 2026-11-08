package model

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
)

// ElectionVoteCounter counts the votes cast in an election. Final is set once the election has closed
// by the database's clock and every counted vote has committed, after which no vote can be counted,
// so the election's votes can be published.
type ElectionVoteCounter struct {
	ElectionID string
	VotesCast  int64
	Final      bool
}

func (c *ElectionVoteCounter) DBInsert(ctx context.Context, tx pgx.Tx) (err error) {
	_, err = tx.Exec(ctx,
		"INSERT INTO election_vote_counters(election_id, votes_cast, final) VALUES($1,$2,$3);",
		c.ElectionID,
		c.VotesCast,
		c.Final)
	if err != nil {
		log.Printf("error inserting election vote counter: %v", err)
	}

	return
}

// FindByElection finds the election's counter
func (c *ElectionVoteCounter) FindByElection(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT votes_cast, final
		FROM election_vote_counters
		WHERE election_id = $1;`,
		c.ElectionID).Scan(&c.VotesCast, &c.Final)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for election vote counter: %v", err)
		return
	}

	found = true

	return
}

// Lock finds the election's counter like FindByElection does, and locks its row until the
// transaction ends, so requests that lock it run one at a time. Freeze skips a final counter without
// waiting for its row, so locking a final counter only holds up other requests that lock it, and
// votes cast after the close, which are rejected anyway.
func (c *ElectionVoteCounter) Lock(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT votes_cast, final
		FROM election_vote_counters
		WHERE election_id = $1
		FOR UPDATE;`,
		c.ElectionID).Scan(&c.VotesCast, &c.Final)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error locking election vote counter: %v", err)
		return
	}

	found = true

	return
}

// Increment counts a vote being cast in the election. The counter's row stays locked until the
// transaction ends, so votes commit in the order they were counted. Final is read back too, and open
// reports whether the election is open by the database's clock, so every API server agrees on when it
// closes. A vote counted by a final counter, or while the election isn't open, can't be cast, and the
// transaction has to be rolled back.
func (c *ElectionVoteCounter) Increment(ctx context.Context, tx pgx.Tx) (open bool, err error) {
	err = tx.QueryRow(ctx,
		`UPDATE election_vote_counters c
		SET votes_cast = c.votes_cast + 1
		FROM elections e
		WHERE c.election_id = $1 AND e.id = c.election_id
		RETURNING c.votes_cast, c.final,
			e.time_open <= extract(epoch FROM now()) AND extract(epoch FROM now()) < e.time_close;`,
		c.ElectionID).Scan(&c.VotesCast, &c.Final, &open)
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("election %s has no vote counter", c.ElectionID)
		log.Print(err)
		return
	} else if err != nil {
		log.Printf("error incrementing election vote counter: %v", err)
		return
	}

	return
}

// Freeze makes the counter final if it isn't already and the election has closed by the database's
// clock, so no more votes can be counted. Until then it does nothing, without waiting for anything, so
// every request that reads the votes can try it. Once the election has closed, it waits for any vote still being cast
// to commit, since each holds the counter's row until it does. frozen reports whether this call made
// the counter final, in which case VotesCast is the final count.
func (c *ElectionVoteCounter) Freeze(ctx context.Context, tx pgx.Tx) (frozen bool, err error) {
	err = tx.QueryRow(ctx,
		`UPDATE election_vote_counters c
		SET final = TRUE
		FROM elections e
		WHERE c.election_id = $1
			AND e.id = c.election_id
			AND NOT c.final
			AND e.time_close <= extract(epoch FROM now())
		RETURNING c.votes_cast;`,
		c.ElectionID).Scan(&c.VotesCast)
	if errors.Is(err, pgx.ErrNoRows) {
		// the election hasn't closed, the counter was already final, or there is no counter
		err = nil
		return
	} else if err != nil {
		log.Printf("error freezing election vote counter: %v", err)
		return
	}

	c.Final = true
	frozen = true

	return
}
