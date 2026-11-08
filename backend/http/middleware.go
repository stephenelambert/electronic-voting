package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"electronic-voting/database"
	"electronic-voting/localcrypto"
	"electronic-voting/localsigner"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"

	"github.com/jackc/pgx/v5"
)

// TxToCtx is middleware that adds a DB transaction to the context.
// If a 4XX or 5XX status code is returned, the transaction is rolled back.
// The response is held until the transaction commits, and becomes a 500 if the commit fails, so a
// client is never told about a change the database doesn't have, or handed something that can't
// be taken back (like a blind signature) without a record of it.
func TxToCtx(handler http.Handler) http.Handler {
	return txToCtx(database.BeginTx, handler)
}

// txToCtx is TxToCtx with how transactions are begun passed in, so tests can use a fake
func txToCtx(beginTx func(context.Context) (pgx.Tx, error), handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tx, err := beginTx(ctx)
		if err != nil {
			log.Printf("error creating transaction %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rollback := func() {
			rollbackCtx, cancel := finishCtx(ctx)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
		defer rollback()

		ctx = context.WithValue(ctx, ctxkey.Key("transaction"), tx)

		rw := newResponseWriterWrapper()
		handler.ServeHTTP(rw, r.WithContext(ctx))

		// abort transaction if any issues
		if rw.Status() >= 400 {
			rollback()
			rw.send(w)
			return
		}

		commitCtx, cancel := finishCtx(ctx)
		defer cancel()
		if err = tx.Commit(commitCtx); err != nil {
			// the response is dropped, since it may hold something that can't be taken back
			log.Printf("error committing transaction for http request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rw.send(w)
	})
}

// finishCtx returns a context for committing or rolling back a request's transaction. It isn't
// cancelled when the client disconnects, since once the handler has done its work, a disconnect
// shouldn't decide whether that work is kept. finishTimeout limits it instead.
func finishCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
}

// BodyToCtx is a middleware function that adds the request body to the
// context for other handlers
func BodyToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// cap the size, since the body is read before the request is authenticated
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			log.Printf("request body larger than %d bytes", maxRequestBodyBytes)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		} else if err != nil {
			log.Printf("error reading request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("request_body"), body)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DtoToCtx parses a JSON object from the request body and puts a pointer of
// it into the request context
func DtoToCtx[T any](ctxKey string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		body := ctx.Value(ctxkey.Key("request_body")).([]byte)

		output := new(T)

		err := json.Unmarshal(body, output)
		if err != nil {
			log.Printf("error decoding request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key(ctxKey), output)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CanonicalDtoToCtx is DtoToCtx for signed request bodies, which must also be exactly the canonical
// encoding of what they parse to (see localcrypto.CanonicalJSON). This is required for consistent auditing.
func CanonicalDtoToCtx[T any](ctxKey string, handler http.Handler) http.Handler {
	return DtoToCtx[T](ctxKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		body := ctx.Value(ctxkey.Key("request_body")).([]byte)
		dto := ctx.Value(ctxkey.Key(ctxKey)).(*T)

		// whitespace, other fields, other field orders, repeated fields and other escapes don't
		// survive the round trip
		canonical, err := localcrypto.CanonicalJSON(dto)
		if err != nil || !bytes.Equal(canonical, body) {
			log.Print("request body is not in canonical form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		handler.ServeHTTP(w, r)
	}))
}

// AuthenticateRequest checks the Authorization field of the request for a timestamp, public key,
// role, jurisdiction and signature, validating them and adding the user account to the context,
// finding certificates as needed. The signature covers action, which names what the route does, this
// instance, the role and jurisdiction, the timestamp and the body (see
// localcrypto.RequestSignedData). Action and instance aren't sent, so a request signed for another
// action or instance fails. The request as it was signed is also added to the context, so handlers
// can store it.
// requiredRole is the required certificate a user must have, and
// jurisdictionOf returns the jurisdiction that certificate must be for. The role and jurisdiction in
// the header must be exactly these, or both empty if no role is required. jurisdictionOf may be nil
// for roles that have no jurisdiction (like global admin), and runs after the route's other
// middleware, so it can read what they added to the context (like the election being voted in).
func AuthenticateRequest(action string, requiredRole *model.CertificateRole, jurisdictionOf func(*http.Request) *string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		auth_headers, ok := r.Header["Authorization"]
		if !ok {
			log.Print("missing authorization header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		auth_header := strings.Replace(auth_headers[0], "Bearer ", "", 1)

		// timestamp, public key, role, jurisdiction and signature. None of them can contain a period
		split_auth_header := strings.Split(auth_header, ".")
		if len(split_auth_header) != 5 {
			log.Printf("authorization token expected 5 parts, got %d", len(split_auth_header))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// make sure timestamp is good
		now := time.Now().UnixMilli()
		timestamp_str := split_auth_header[0]
		request_timestamp, err := localcrypto.ParseRequestTimestamp(timestamp_str)
		if err != nil {
			log.Printf("error parsing authorization timestamp from %s: %v", timestamp_str, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if request_timestamp < now-allowedTimeDrift || request_timestamp > now+allowedTimeDrift {
			log.Printf("authorization timestamp (%d) too far from current time (%d)", request_timestamp, now)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// make sure public key is an actual public key
		pem_bytes, err := base64.StdEncoding.DecodeString(split_auth_header[1])
		if err != nil {
			log.Printf("error decoding base64 public key")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// normalize so the key matches how it is stored in the database. Accounts' keys are all P-384,
		// which is the only kind browsers check the stored request's signature with
		public_key_pem, ecdsa_key, err := localcrypto.ParseAccountPublicKey(string(pem_bytes))
		if err != nil {
			log.Printf("error parsing public key: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// the role and jurisdiction of the certificate the signer is acting under. A key has at most one
		// active certificate for each role and jurisdiction, so together they name it
		role := split_auth_header[2]
		jurisdiction := split_auth_header[3]

		// decompose signature parts
		signature_bytes, err := localcrypto.DecodeRequestSignature(split_auth_header[4])
		if err != nil {
			log.Printf("error decoding signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sig_r := &big.Int{}
		sig_r.SetBytes(signature_bytes[:localcrypto.RequestSignatureBytes/2])
		sig_s := &big.Int{}
		sig_s.SetBytes(signature_bytes[localcrypto.RequestSignatureBytes/2:])

		// build value to hash, with this route's action and this instance, so a request signed for
		// another action or instance fails
		// allow empty body (e.g. GET requests)
		body, _ := ctx.Value(ctxkey.Key("request_body")).([]byte)
		instance := localsigner.Instance()
		val_to_hash := localcrypto.RequestSignedData(action, instance, role, jurisdiction, timestamp_str, body)

		// hash the value
		hashed_val := sha256.Sum256(val_to_hash)

		signature_good := ecdsa.Verify(ecdsa_key, hashed_val[:], sig_r, sig_s)
		if !signature_good {
			log.Print("invalid signature in authorization header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// for now, each route accepts exactly the role and jurisdiction it requires, or neither if it
		// requires no role
		var jurisdictionID *string
		required_role, required_jurisdiction := "", ""
		if requiredRole != nil {
			required_role = string(*requiredRole)
			if jurisdictionOf != nil {
				jurisdictionID = jurisdictionOf(r)
			}
		}
		if jurisdictionID != nil {
			required_jurisdiction = *jurisdictionID
		}
		if role != required_role || jurisdiction != required_jurisdiction {
			log.Printf("authorization acts as role %q in jurisdiction %q, but the route requires role %q in jurisdiction %q", role, jurisdiction, required_role, required_jurisdiction)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// the parts the signature covers are kept exactly as signed, so it can be checked again
		signedRequest := model.SignedRequest{
			Action:           action,
			Instance:         instance,
			Role:             requiredRole,
			JurisdictionID:   jurisdictionID,
			RequestTimestamp: timestamp_str,
			Body:             string(body),
			PublicKey:        public_key_pem,
			Signature:        base64.StdEncoding.EncodeToString(signature_bytes),
		}

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

		// no role required, don't worry about certs
		// TODO: split this into two middleware functions for with certs vs without
		if requiredRole == nil {
			account := &model.Account{
				SigningKey: &model.SigningKeyLite{
					PublicKey: public_key_pem,
				},
			}
			acc_found, err := account.FindByPublicKey(ctx, tx)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if !acc_found {
				log.Print("account not found for authorization")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx = context.WithValue(ctx, ctxkey.Key("account"), account)
			ctx = context.WithValue(ctx, ctxkey.Key("signed_request"), signedRequest)
			handler.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// role required, find the certificate the role and jurisdiction name
		account := &model.AccountWithOneCertificate{
			SigningKey: &model.SigningKeyLiteWithOneCertificate{
				PublicKey: public_key_pem,
			},
		}

		acc_found, err := account.FindByPublicKeyAndRole(ctx, tx, *requiredRole, jurisdictionID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !acc_found || account.SigningKey == nil || account.SigningKey.Certificate == nil {
			log.Print("account not found for authorization")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		signedRequest.CertificateID = &account.SigningKey.Certificate.ID
		signedRequest.CertPEM = &account.SigningKey.Certificate.CertPEM

		ctx = context.WithValue(ctx, ctxkey.Key("account"), account)
		ctx = context.WithValue(ctx, ctxkey.Key("signed_request"), signedRequest)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
