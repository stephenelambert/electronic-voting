package model

import (
	"context"
	"electronic-voting/util/dbcrypt"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

// OpaqueServerKey is the server's OPAQUE key pair, as encoded ristretto255 scalar and point. There's
// only ever one.
type OpaqueServerKey struct {
	PrivateKey        dbcrypt.EncryptedBytes
	PublicKey         []byte
	CreationTimestamp int64
}

func (k *OpaqueServerKey) DbInsert(ctx context.Context, tx pgx.Tx) (err error) {
	_, err = tx.Exec(ctx,
		"INSERT INTO opaque_server_key(private_key, public_key, creation_timestamp) VALUES($1,$2,$3);",
		k.PrivateKey,
		k.PublicKey,
		k.CreationTimestamp)
	if err != nil {
		log.Printf("error inserting OPAQUE server key: %v", err)
	}

	return
}

// Find finds the server's key pair
func (k *OpaqueServerKey) Find(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		"SELECT private_key, public_key, creation_timestamp FROM opaque_server_key;").
		Scan(&k.PrivateKey, &k.PublicKey, &k.CreationTimestamp)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for OPAQUE server key: %v", err)
		return
	}

	found = true

	return
}
