package model

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// likeEscaper escapes the LIKE wildcards (and the escape character itself) so user input is
// matched literally
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

type Account struct {
	ID       string
	Username string
	// OpaqueRecord is the account's OPAQUE registration record, or nil if it hasn't registered yet.
	// Only FindByUsername fills it in.
	OpaqueRecord []byte
	// SetupTokenHash is the SHA-256 hash of the token that claims an admin account the API created,
	// or nil. Only FindByUsername fills it in.
	SetupTokenHash []byte
	// SigningKey needs to be updated in the database separately from the rest of the object
	SigningKey *SigningKeyLite
	IsAdmin    bool
	AesKey     string
}

type Accounts []Account

// AccountWithOneCertificate is used for queries to determine authorization
type AccountWithOneCertificate struct {
	ID       string
	Username string
	// SigningKey needs to be updated in the database separately from the rest of the object
	SigningKey *SigningKeyLiteWithOneCertificate
	// Authorization is the signed request that authorized the certificate, like an admin's voter
	// authorization. Only FindByJurisdictionAndRole fills it in.
	Authorization *SignedRequest
	IsAdmin       bool
	AesKey        string
}

type AccountsWithOneCertificate []AccountWithOneCertificate

func (acc *Account) DbInsert(ctx context.Context, tx pgx.Tx) (err error) {
	if acc.ID == "" {
		var uid uuid.UUID
		uid, err = uuid.NewRandom()
		if err != nil {
			return
		}

		acc.ID = uid.String()
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO accounts(id, username, opaque_record, setup_token_hash, is_admin, aes_key) VALUES($1,$2,$3,$4,$5,$6);",
		acc.ID,
		acc.Username,
		acc.OpaqueRecord,
		acc.SetupTokenHash,
		acc.IsAdmin,
		acc.AesKey)

	if err != nil {
		log.Printf("error inserting account: %v", err)
	}

	return
}

// Update writes every field, so acc has to come from FindByUsername, the only finder that fills in
// OpaqueRecord and SetupTokenHash. Otherwise the account's registration record would be erased.
func (acc *Account) Update(ctx context.Context, tx pgx.Tx) (err error) {
	_, err = tx.Exec(ctx,
		"UPDATE accounts SET opaque_record=$1, setup_token_hash=$2, is_admin=$3, aes_key=$4 WHERE id=$5;",
		acc.OpaqueRecord,
		acc.SetupTokenHash,
		acc.IsAdmin,
		acc.AesKey,
		acc.ID)
	return
}

// Claim registers an account the API created with acc's registration record and AES key, and clears
// its setup token, unless the account has registered already. claimed is false if it has, e.g.
// because a concurrent registration claimed it first. A claim waits for a concurrent one to commit,
// so only one of them can succeed.
func (acc *Account) Claim(ctx context.Context, tx pgx.Tx) (claimed bool, err error) {
	tag, err := tx.Exec(ctx,
		`UPDATE accounts
		SET opaque_record = $1, setup_token_hash = NULL, aes_key = $2
		WHERE id = $3
			AND opaque_record IS NULL;`,
		acc.OpaqueRecord,
		acc.AesKey,
		acc.ID)
	if err != nil {
		log.Printf("error claiming account: %v", err)
		return
	}
	if tag.RowsAffected() == 0 {
		return
	}

	acc.SetupTokenHash = nil
	claimed = true

	return
}

// ValidUsername reports whether username can be used for an account, with no leading or trailing whitespace
func ValidUsername(username string) bool {
	return username != "" && strings.TrimSpace(username) == username
}

// SetSetupToken sets the token that claims the account, which is stored hashed
func (acc *Account) SetSetupToken(token string) {
	hash := sha256.Sum256([]byte(token))
	acc.SetupTokenHash = hash[:]
}

// SetupTokenMatches reports whether token claims the account
func (acc *Account) SetupTokenMatches(token string) bool {
	hash := sha256.Sum256([]byte(token))
	return acc.SetupTokenHash != nil && subtle.ConstantTimeCompare(hash[:], acc.SetupTokenHash) == 1
}

// CountAccountsWithOpaqueRecords counts the accounts that have registered, which all depend on the
// server's OPAQUE key
func CountAccountsWithOpaqueRecords(ctx context.Context, tx pgx.Tx) (count int, err error) {
	err = tx.QueryRow(ctx, "SELECT count(*) FROM accounts WHERE opaque_record IS NOT NULL;").Scan(&count)
	return
}

func (acc *Account) FindByUsername(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	var nilSigningKey nilSigningKeyLite

	err = tx.QueryRow(ctx,
		`SELECT
			accounts.id,
			username,
			opaque_record,
			setup_token_hash,
			signing_keys.id,
			signing_keys.public_key,
			signing_keys.private_key,
			is_admin,
			aes_key
		FROM accounts
		LEFT JOIN signing_keys
			ON signing_keys.owner_id = accounts.id
			AND signing_keys.owner_type = 'account'
			AND signing_keys.deactivation_timestamp IS NULL
		WHERE username=$1
		LIMIT 1;`,
		acc.Username).Scan(&acc.ID,
		&acc.Username,
		&acc.OpaqueRecord,
		&acc.SetupTokenHash,
		&nilSigningKey.ID,
		&nilSigningKey.PublicKey,
		&nilSigningKey.PrivateKey,
		&acc.IsAdmin,
		&acc.AesKey)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for account by username: %v", err)
		return
	}

	found = true

	if nilSigningKey.ID != nil {
		acc.SigningKey = nilSigningKey.toSKL()
	}

	return
}

func (acc *Account) FindByPublicKey(ctx context.Context, tx pgx.Tx) (found bool, err error) {
	if acc.SigningKey == nil {
		found = false
		return
	}

	var nilSigningKey nilSigningKeyLite

	err = tx.QueryRow(ctx,
		`SELECT
			accounts.id,
			username,
			signing_keys.id,
			signing_keys.public_key,
			signing_keys.private_key,
			is_admin,
			aes_key
		FROM accounts
		LEFT JOIN signing_keys
			ON signing_keys.owner_id = accounts.id
			AND signing_keys.owner_type = 'account'
			AND signing_keys.deactivation_timestamp IS NULL
		WHERE public_key=$1
		LIMIT 1;`,
		acc.SigningKey.PublicKey).Scan(&acc.ID,
		&acc.Username,
		&nilSigningKey.ID,
		&nilSigningKey.PublicKey,
		&nilSigningKey.PrivateKey,
		&acc.IsAdmin,
		&acc.AesKey)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for account by public key: %v", err)
		return
	}

	found = true

	if nilSigningKey.ID != nil {
		acc.SigningKey = nilSigningKey.toSKL()
	}

	return
}

// SearchByUsernamePrefix finds accounts with an active signing key whose usernames start with
// prefix, ignoring case. Only the username and the public key of the signing key are populated.
func (accs *Accounts) SearchByUsernamePrefix(ctx context.Context, tx pgx.Tx, prefix string, limit int) (err error) {
	if accs == nil {
		return
	}

	rows, err := tx.Query(ctx,
		`SELECT
			accounts.username,
			signing_keys.public_key
		FROM accounts
		INNER JOIN signing_keys
			ON signing_keys.owner_id = accounts.id
			AND signing_keys.owner_type = 'account'
			AND signing_keys.deactivation_timestamp IS NULL
		WHERE lower(accounts.username) LIKE lower($1::text) || '%'
		ORDER BY accounts.username
		LIMIT $2;`,
		likeEscaper.Replace(prefix),
		limit)
	if err != nil {
		log.Printf("error querying for accounts by username prefix: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		acc := Account{
			SigningKey: &SigningKeyLite{},
		}

		if err = rows.Scan(&acc.Username, &acc.SigningKey.PublicKey); err != nil {
			log.Printf("error scanning for account by username prefix: %v", err)
			return
		}

		*accs = append(*accs, acc)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for accounts by username prefix: %v", err)
		return
	}

	return
}

// FindByJurisdictionAndRole finds a page of accounts holding an active certificate for the role in
// the jurisdiction, ordered by username, optionally filtered to usernames starting with
// usernamePrefix (ignoring case). Only the account ID, username, signing key ID and public key,
// certificate, and the signed request that authorized the certificate are populated. total is the
// number of matching accounts across all pages.
func (accs *AccountsWithOneCertificate) FindByJurisdictionAndRole(ctx context.Context, tx pgx.Tx, jurisdictionID string, role CertificateRole, usernamePrefix *string, limit, offset int) (total int, err error) {
	if accs == nil {
		return
	}

	const joins = `
		INNER JOIN signing_keys
			ON signing_keys.public_key = certificates.pub_pem
			AND signing_keys.owner_type = 'account'
		INNER JOIN accounts
			ON accounts.id = signing_keys.owner_id`
	const conditions = `
		WHERE certificates.jurisdiction_id = $1
			AND certificates.role = $2
			AND certificates.revocation_timestamp IS NULL`
	const usernameCondition = `
			AND lower(accounts.username) LIKE lower($3::text) || '%'`

	args := []any{jurisdictionID, role}

	// without a username filter, count from the index on certificates alone, since joining is
	// much slower for large jurisdictions. this matches the joined rows because every certificate
	// key exists in signing_keys (foreign key), and certificates with a jurisdiction are only issued
	// to keys owned by accounts, each with the signed request that authorized it.
	countQuery := `SELECT count(*) FROM certificates` + conditions + `;`
	pageQuery := `SELECT
			accounts.id,
			accounts.username,
			signing_keys.id,
			signing_keys.public_key,
			certificates.id,
			certificates.serial_number,
			certificates.pub_pem,
			certificates.cert_pem,
			certificates.not_before,
			certificates.not_after,
			certificates.signer_cert_id,
			certificates.jurisdiction_id,
			certificates.role,
			certificates.crl,
			certificates.creation_timestamp,
			certificates.revocation_timestamp,
			certificates.revocation_reason,
			certificates.signed_request_id,
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
			authorization_certificates.cert_pem
		FROM certificates` + joins + `
		INNER JOIN signed_requests
			ON signed_requests.id = certificates.signed_request_id
		LEFT JOIN certificates AS authorization_certificates
			ON authorization_certificates.id = signed_requests.certificate_id` + conditions

	if usernamePrefix != nil {
		args = append(args, likeEscaper.Replace(*usernamePrefix))
		countQuery = `SELECT count(*) FROM certificates` + joins + conditions + usernameCondition + `;`
		pageQuery += usernameCondition
	}

	err = tx.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		log.Printf("error counting accounts by jurisdiction and role: %v", err)
		return
	}

	pageQuery += fmt.Sprintf(`
		ORDER BY accounts.username, certificates.id
		LIMIT $%d OFFSET $%d;`, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := tx.Query(ctx, pageQuery, args...)
	if err != nil {
		log.Printf("error querying for accounts by jurisdiction and role: %v", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		acc := AccountWithOneCertificate{
			SigningKey: &SigningKeyLiteWithOneCertificate{
				Certificate: &Certificate{},
			},
			Authorization: &SignedRequest{},
		}
		cert := acc.SigningKey.Certificate
		authorization := acc.Authorization

		err = rows.Scan(&acc.ID,
			&acc.Username,
			&acc.SigningKey.ID,
			&acc.SigningKey.PublicKey,
			&cert.ID,
			&cert.SerialNumber,
			&cert.PubPEM,
			&cert.CertPEM,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.SignerCertID,
			&cert.JurisdictionID,
			&cert.Role,
			&cert.CRL,
			&cert.CreationTimestamp,
			&cert.RevocationTimestamp,
			&cert.RevocationReason,
			&cert.SignedRequestID,
			&authorization.ID,
			&authorization.Action,
			&authorization.Instance,
			&authorization.Role,
			&authorization.JurisdictionID,
			&authorization.RequestTimestamp,
			&authorization.Body,
			&authorization.PublicKey,
			&authorization.Signature,
			&authorization.CertificateID,
			&authorization.CertPEM)
		if err != nil {
			log.Printf("error scanning for account by jurisdiction and role: %v", err)
			return
		}

		*accs = append(*accs, acc)
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while running query for accounts by jurisdiction and role: %v", err)
		return
	}

	return
}

func (acc *AccountWithOneCertificate) FindByPublicKeyAndRole(ctx context.Context, tx pgx.Tx, role CertificateRole, jurisdictionID *string) (found bool, err error) {
	if acc.SigningKey.PublicKey == "" || role == "" {
		return
	}

	var nilSigningKey nilSigningKeyLite
	var nilCert nilCertificate

	err = tx.QueryRow(ctx,
		`SELECT
			accounts.id,
			username,
			signing_keys.id,
			signing_keys.public_key,
			signing_keys.private_key,
			is_admin,
			aes_key,
			certificates.id,
			certificates.serial_number,
			certificates.pub_pem,
			certificates.cert_pem,
			certificates.not_before,
			certificates.not_after,
			certificates.signer_cert_id,
			certificates.jurisdiction_id,
			certificates.role,
			certificates.crl,
			certificates.creation_timestamp,
			certificates.revocation_timestamp,
			certificates.revocation_reason,
			certificates.signed_request_id
		FROM accounts
		INNER JOIN signing_keys
			ON signing_keys.owner_id = accounts.id
			AND signing_keys.owner_type = 'account'
			AND signing_keys.deactivation_timestamp IS NULL
		LEFT JOIN certificates
			ON certificates.pub_pem = signing_keys.public_key
			AND certificates.role=$1
			AND certificates.jurisdiction_id IS NOT DISTINCT FROM $2
			AND certificates.revocation_timestamp IS NULL
		WHERE public_key=$3
		LIMIT 1;`,
		role,
		jurisdictionID,
		acc.SigningKey.PublicKey).Scan(&acc.ID,
		&acc.Username,
		&nilSigningKey.ID,
		&nilSigningKey.PublicKey,
		&nilSigningKey.PrivateKey,
		&acc.IsAdmin,
		&acc.AesKey,
		&nilCert.ID,
		&nilCert.SerialNumber,
		&nilCert.PubPEM,
		&nilCert.CertPEM,
		&nilCert.NotBefore,
		&nilCert.NotAfter,
		&nilCert.SignerCertID,
		&nilCert.JurisdictionID,
		&nilCert.Role,
		&nilCert.CRL,
		&nilCert.CreationTimestamp,
		&nilCert.RevocationTimestamp,
		&nilCert.RevocationReason,
		&nilCert.SignedRequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	} else if err != nil {
		log.Printf("error querying for account by public key and role: %v", err)
		return
	}

	found = true

	if nilSigningKey.ID == nil {
		return
	}

	skl := nilSigningKey.toSKL()
	acc.SigningKey = &SigningKeyLiteWithOneCertificate{
		ID:         skl.ID,
		PrivateKey: skl.PrivateKey,
		PublicKey:  skl.PublicKey,
	}

	if nilCert.ID != nil {
		acc.SigningKey.Certificate = nilCert.toCert()
	}

	return
}
