package model

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PendingLogin is a login between the server's KE2 and the client's KE3, holding the MAC the
// client's KE3 must have
type PendingLogin struct {
	ID                string
	AccountID         string
	ExpectedClientMAC []byte
	CreationTimestamp int64
}

func (pl *PendingLogin) DbInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if pl.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		pl.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO pending_logins(id, account_id, expected_client_mac, creation_timestamp) VALUES($1,$2,$3,$4);",
		pl.ID,
		pl.AccountID,
		pl.ExpectedClientMAC,
		pl.CreationTimestamp)
	if err != nil {
		log.Printf("error inserting pending login: %v", err)
	}

	return
}

// Take deletes the pending login with pl's ID and fills in the rest of pl, so each one is only used
// once, and returns the username of its account
func (pl *PendingLogin) Take(ctx context.Context, tx pgx.Tx) (username string, found bool, err error) {
	err = tx.QueryRow(ctx,
		`DELETE FROM pending_logins
		USING accounts
		WHERE pending_logins.id = $1
			AND accounts.id = pending_logins.account_id
		RETURNING
			pending_logins.account_id,
			pending_logins.expected_client_mac,
			pending_logins.creation_timestamp,
			accounts.username;`,
		pl.ID).Scan(&pl.AccountID, &pl.ExpectedClientMAC, &pl.CreationTimestamp, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error taking pending login: %v", err)
		return
	}

	found = true

	return
}

// DeletePendingLoginsBefore deletes the pending logins created before timestamp, which have expired
func DeletePendingLoginsBefore(ctx context.Context, tx pgx.Tx, timestamp int64) (err error) {
	_, err = tx.Exec(ctx, "DELETE FROM pending_logins WHERE creation_timestamp < $1;", timestamp)
	if err != nil {
		log.Printf("error deleting expired pending logins: %v", err)
	}

	return
}
