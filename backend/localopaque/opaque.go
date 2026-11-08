// Package localopaque is the API's side of OPAQUE (RFC 9807), the password protocol accounts register
// and log in with, so the API never sees a password or anything it could check one against without
// the OPRF seed. It uses the ristretto255 and SHA-512 configuration. The clients' key stretching
// (Argon2id) happens only in the browser, so it isn't configured here.
package localopaque

import (
	"context"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bytemare/opaque"
	"github.com/jackc/pgx/v5"
)

// OPRFSeedEnvVar is the environment variable the OPRF seed is read from. It's base64 for 64 random
// bytes. It's only read from the environment, since command-line flags can be seen in process
// listings.
const OPRFSeedEnvVar = "OPAQUE_OPRF_SEED"

// PendingLoginLifetime is how long a client has to finish a login after starting it, in seconds. It
// has to cover the client's key stretching, which can take a few seconds on slow devices.
const PendingLoginLifetime int64 = 60

// ErrInvalidMessage is returned when a client's OPAQUE message can't be decoded or is invalid
var ErrInvalidMessage = errors.New("invalid OPAQUE message")

// encoding is how OPAQUE messages are sent in requests and responses: unpadded base64url, which is
// what the frontend's OPAQUE library (@serenity-kit/opaque) uses
var encoding = base64.RawURLEncoding

// server is the OPAQUE server, set up by Init
var server *opaque.Server

// Init reads the OPRF seed from the environment and loads the server's key pair from the database,
// creating it if no account has registered yet. A key pair can't be replaced once accounts have
// registered, since every registration record depends on it, so if it's missing then, Init fails
// rather than locking every account out.
func Init(ctx context.Context) (err error) {
	tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

	seed, err := ParseOPRFSeed(os.Getenv(OPRFSeedEnvVar))
	if err != nil {
		return
	}

	key := &model.OpaqueServerKey{}
	found, err := key.Find(ctx, tx)
	if err != nil {
		return fmt.Errorf("error querying for OPAQUE server key: %w", err)
	}

	if !found {
		var registered int
		registered, err = model.CountAccountsWithOpaqueRecords(ctx, tx)
		if err != nil {
			return fmt.Errorf("error counting registered accounts: %w", err)
		}
		if registered > 0 {
			return fmt.Errorf("the OPAQUE server key is missing, but %d accounts have registered with it. Restore it, since a new key would lock every account out", registered)
		}

		key.PrivateKey, key.PublicKey = generateKey()
		key.CreationTimestamp = time.Now().Unix()
		if err = key.DbInsert(ctx, tx); err != nil {
			return fmt.Errorf("error inserting OPAQUE server key: %w", err)
		}
	}

	server, err = newServer(seed, key.PrivateKey, key.PublicKey)
	return
}

// ParseOPRFSeed decodes the OPRF seed from base64, which must be 64 bytes, the size OPAQUE uses
// with SHA-512
func ParseOPRFSeed(encoded string) ([]byte, error) {
	const generate = "generate one with: openssl rand -base64 64 | tr -d '\\n'"

	if encoded == "" {
		return nil, fmt.Errorf("%s must be set to the OPRF seed; %s", OPRFSeedEnvVar, generate)
	}

	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s isn't valid base64 (%w); %s", OPRFSeedEnvVar, err, generate)
	}

	if size := opaque.DefaultConfiguration().Hash.Size(); len(seed) != size {
		return nil, fmt.Errorf("%s must decode to %d bytes, not %d; %s", OPRFSeedEnvVar, size, len(seed), generate)
	}

	return seed, nil
}

// generateKey generates a key pair for the server, returning the encoded private and public keys
func generateKey() (privateKey, publicKey []byte) {
	sk, pk := opaque.DefaultConfiguration().KeyGen()
	return sk.Encode(), pk.Encode()
}

// newServer sets up an OPAQUE server with the OPRF seed and the encoded key pair
func newServer(seed, privateKey, publicKey []byte) (*opaque.Server, error) {
	s, err := opaque.DefaultConfiguration().Server()
	if err != nil {
		return nil, fmt.Errorf("error creating OPAQUE server: %w", err)
	}

	sk, err := s.Deserialize.DecodePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding OPAQUE server private key: %w", err)
	}

	// the identity is the public key, which is also what the RFC uses when there's none, so clients
	// don't send one. It's set explicitly because the library can't decode key material it encoded
	// without one, in case the key material is ever stored that way
	err = s.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey:     sk,
		PublicKeyBytes: publicKey,
		OPRFGlobalSeed: seed,
		Identity:       publicKey,
	})
	if err != nil {
		// this also checks that the public key is the private key's
		return nil, fmt.Errorf("invalid OPAQUE server key material: %w", err)
	}

	return s, nil
}

// RegistrationResponse answers a client's registration request for the account with username. The
// username identifies the client's OPRF key, so it has to be the same every time it logs in.
func RegistrationResponse(username, request string) (response string, err error) {
	raw, err := encoding.DecodeString(request)
	if err != nil {
		return "", errors.Join(ErrInvalidMessage, err)
	}

	req, err := server.Deserialize.RegistrationRequest(raw)
	if err != nil {
		return "", errors.Join(ErrInvalidMessage, err)
	}

	resp, err := server.RegistrationResponse(req, []byte(username), nil)
	if err != nil {
		return "", errors.Join(ErrInvalidMessage, err)
	}

	return encoding.EncodeToString(resp.Serialize()), nil
}

// ParseRecord checks a client's registration record, returning it as it's stored
func ParseRecord(record string) ([]byte, error) {
	raw, err := encoding.DecodeString(record)
	if err != nil {
		return nil, errors.Join(ErrInvalidMessage, err)
	}

	parsed, err := server.Deserialize.RegistrationRecord(raw)
	if err != nil {
		return nil, errors.Join(ErrInvalidMessage, err)
	}

	return parsed.Serialize(), nil
}

// StartLogin answers a client's KE1 for the account with username and its registration record,
// returning the KE2 to send back and the MAC the client's KE3 must hold. The username is also the
// client's identity, which the client must use too.
func StartLogin(username string, record []byte, ke1 string) (ke2 string, expectedClientMAC []byte, err error) {
	parsedRecord, err := server.Deserialize.RegistrationRecord(record)
	if err != nil {
		return "", nil, fmt.Errorf("error decoding stored registration record: %w", err)
	}

	raw, err := encoding.DecodeString(ke1)
	if err != nil {
		return "", nil, errors.Join(ErrInvalidMessage, err)
	}

	parsedKE1, err := server.Deserialize.KE1(raw)
	if err != nil {
		return "", nil, errors.Join(ErrInvalidMessage, err)
	}

	// the record was checked when it was stored, so this only fails for the client's KE1
	response, output, err := server.GenerateKE2(parsedKE1, &opaque.ClientRecord{
		RegistrationRecord:   parsedRecord,
		CredentialIdentifier: []byte(username),
		ClientIdentity:       []byte(username),
	})
	if err != nil {
		return "", nil, errors.Join(ErrInvalidMessage, err)
	}

	return encoding.EncodeToString(response.Serialize()), output.ClientMAC, nil
}

// FinishLogin checks a client's KE3 against the MAC StartLogin returned for its login, which shows
// the client knows the account's password. The session key OPAQUE also agrees on isn't used, since
// requests are authenticated with signatures from the account's key instead.
func FinishLogin(ke3 string, expectedClientMAC []byte) error {
	raw, err := encoding.DecodeString(ke3)
	if err != nil {
		return errors.Join(ErrInvalidMessage, err)
	}

	parsed, err := server.Deserialize.KE3(raw)
	if err != nil {
		return errors.Join(ErrInvalidMessage, err)
	}

	return server.LoginFinish(parsed, expectedClientMAC)
}
