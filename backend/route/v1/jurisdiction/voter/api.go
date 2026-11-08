package voter

import (
	"context"
	"electronic-voting/database"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// authorize issues a voter certificate for the jurisdiction in the context to the account
// with the public key in the request. The certificate references the admin's signed request, which
// is stored with it.
func authorize(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*request)

		// the signed request says which jurisdiction the voter is authorized in, so it has to be this one
		if req.JurisdictionID != jurisdiction.ID {
			log.Print("voter authorization is for a different jurisdiction")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// the key must already be in normalized form, which is how accounts' keys are served
		publicKey, _, err := localcrypto.NormalizePublicKeyPEM(req.PublicKey)
		if err != nil {
			log.Printf("invalid public key in voter authorization: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if publicKey != req.PublicKey {
			log.Print("public key in voter authorization is not in normalized form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// only authorize keys that are the active key of an account
		account := &model.Account{
			SigningKey: &model.SigningKeyLite{
				PublicKey: publicKey,
			},
		}
		found, err := account.FindByPublicKey(ctx, tx)
		if err != nil {
			log.Printf("error querying account for voter authorization: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found {
			log.Print("no account found for public key in voter authorization")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err = signedRequest.DBInsert(ctx, tx); err != nil {
			log.Printf("error inserting signed request for voter authorization: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		cert, status, err := certificate.SystemSignAndInsertCert(ctx, model.CertificateVoterRole, &jurisdiction.ID, publicKey, &signedRequest.ID)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			log.Printf("account %s already authorized as voter in jurisdiction %s", account.ID, jurisdiction.ID)
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error creating voter cert: %v", err)
			w.WriteHeader(status)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("certificate"), cert)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

const (
	// defaultPageSize is the number of voters returned when no limit is given
	defaultPageSize = 50

	// maxPageSize is the largest limit allowed when listing voters
	maxPageSize = 100
)

// allToCtx adds a page of the voters for the jurisdiction in the context, and the total number of
// voters, to the context. The page is controlled by the "limit" and "offset" query parameters, and
// the optional "username" query parameter filters to usernames starting with it.
func allToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)
		query := r.URL.Query()

		limit, ok := intQueryParam(query, "limit", defaultPageSize, 1, maxPageSize)
		if !ok {
			log.Printf("invalid limit in voter listing: %s", query.Get("limit"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		offset, ok := intQueryParam(query, "offset", 0, 0, math.MaxInt32)
		if !ok {
			log.Printf("invalid offset in voter listing: %s", query.Get("offset"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var usernamePrefix *string
		if username := query.Get("username"); username != "" {
			usernamePrefix = &username
		}

		voters := model.AccountsWithOneCertificate{}
		total, err := voters.FindByJurisdictionAndRole(ctx, tx, jurisdiction.ID, model.CertificateVoterRole, usernamePrefix, limit, offset)
		if err != nil {
			log.Printf("error listing voters: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("voters"), voters)
		ctx = context.WithValue(ctx, ctxkey.Key("voters_total"), total)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorizationsToCtx adds the voter authorizations for the jurisdiction in the context to the
// context: its active voter certificates, in the order they were issued, each with the admin's signed
// request that authorized it
func authorizationsToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)

		authorizations := model.AuthorizedCertificates{}
		err := authorizations.FindByJurisdictionAndRole(ctx, tx, jurisdiction.ID, model.CertificateVoterRole)
		if err != nil {
			log.Printf("error listing voter authorizations: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("voter_authorizations"), authorizations)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// intQueryParam parses the named query parameter as an integer between minValue and maxValue
// (inclusive), returning def if the parameter isn't given. ok is false if the parameter is invalid.
func intQueryParam(query url.Values, name string, def, minValue, maxValue int) (value int, ok bool) {
	if !query.Has(name) {
		return def, true
	}

	value, err := strconv.Atoi(query.Get(name))
	if err != nil || value < minValue || value > maxValue {
		return 0, false
	}

	return value, true
}
