package model

import (
	"context"
	"electronic-voting/util/dbcrypt"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type KeyOwnerType string

const (
	KeyAccountOwner  KeyOwnerType = "account"
	KeySystemOwner   KeyOwnerType = "system"
	KeyElectionOwner KeyOwnerType = "election"
)

type SigningKey struct {
	ID                    string
	PrivateKey            dbcrypt.EncryptedString
	PublicKey             string
	OwnerType             KeyOwnerType
	OwnerID               *string
	CreationTimestamp     int64
	DeactivationTimestamp *int64
}

type SigningKeyLite struct {
	ID         string
	PrivateKey dbcrypt.EncryptedString
	PublicKey  string
}

type nilSigningKeyLite struct {
	ID         *string
	PrivateKey *dbcrypt.EncryptedString
	PublicKey  *string
}

type SigningKeyLiteWithOneCertificate struct {
	ID          string
	PrivateKey  dbcrypt.EncryptedString
	PublicKey   string
	Certificate *Certificate
}

func (sk *SigningKey) DbInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if sk.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		sk.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO signing_keys(id, private_key, public_key, owner_type, owner_id, creation_timestamp, deactivation_timestamp) VALUES($1,$2,$3,$4,$5,$6,$7);",
		sk.ID,
		sk.PrivateKey,
		sk.PublicKey,
		sk.OwnerType,
		sk.OwnerID,
		sk.CreationTimestamp,
		sk.DeactivationTimestamp)

	if err != nil {
		log.Printf("error inserting signing key: %v", err)
	}

	return
}

// ClaimElectionKey makes the active election key with the signing key's public key belong to the
// election, if no election has claimed it yet. claimed is false if there is no such key, e.g.
// because it was already claimed.
func (sk *SigningKey) ClaimElectionKey(ctx context.Context, tx pgx.Tx, electionID string) (claimed bool, err error) {
	tag, err := tx.Exec(ctx,
		`UPDATE signing_keys
		SET owner_id = $1
		WHERE public_key = $2
			AND owner_type = $3
			AND owner_id IS NULL
			AND deactivation_timestamp IS NULL;`,
		electionID,
		sk.PublicKey,
		KeyElectionOwner)
	if err != nil {
		log.Printf("error claiming election key: %v", err)
		return
	}
	if tag.RowsAffected() == 0 {
		return
	}

	sk.OwnerType = KeyElectionOwner
	sk.OwnerID = &electionID
	claimed = true

	return
}

func (sk *SigningKey) FindByPublicKey(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	err = tx.QueryRow(ctx,
		`SELECT
			id,
			private_key,
			public_key,
			owner_type,
			owner_id,
			creation_timestamp
		FROM signing_keys
		WHERE public_key=$1;`,
		sk.PublicKey).Scan(&sk.ID,
		&sk.PrivateKey,
		&sk.PublicKey,
		&sk.OwnerType,
		&sk.OwnerID,
		&sk.CreationTimestamp)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for signing key by public key: %v", err)
		return
	}

	found = true

	return
}

func (nskl *nilSigningKeyLite) toSKL() (skl *SigningKeyLite) {
	if nskl.ID != nil {
		skl = &SigningKeyLite{
			ID: *nskl.ID,
		}
	}

	if nskl.PrivateKey != nil {
		skl.PrivateKey = *nskl.PrivateKey
	}

	if nskl.PublicKey != nil {
		skl.PublicKey = *nskl.PublicKey
	}

	return
}
