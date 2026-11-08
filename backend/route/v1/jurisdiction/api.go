package jurisdiction

import (
	"context"
	"electronic-voting/database"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

func toCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

		vars := mux.Vars(r)
		id := vars["id"]

		// ids in paths must be canonical, like ids in request bodies: handlers check the ids in signed
		// bodies against this one, so a signed body must name the stored id exactly
		if !localcrypto.UUIDIsCanonical(id) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		jur := model.Jurisdiction{
			ID: id,
		}

		found, err := jur.FindById(ctx, tx)
		if err != nil {
			log.Printf("error querying for jurisdiction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("jurisdiction"), jur)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// signedRequestToCtx finds the signed request that created the jurisdiction in the context. toCtx
// leaves it out, so only the routes that show it query for it.
func signedRequestToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)

		if err := jurisdiction.FindSignedRequest(ctx, tx); err != nil {
			log.Printf("error querying for signed request that created jurisdiction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("jurisdiction"), jurisdiction)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func create(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*request)

		// the client generates the id, so the signed request covers it
		if !localcrypto.UUIDIsCanonical(req.ID) {
			log.Print("jurisdiction id in request is not a canonical uuid")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		jurisdiction := model.Jurisdiction{
			ID:               req.ID,
			Name:             req.Name,
			Info:             req.Info,
			CreatedTimestamp: time.Now().Unix(),
			SignedRequest:    signedRequest,
		}
		err := jurisdiction.DBInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			log.Printf("jurisdiction %s or one named %q already exists", req.ID, req.Name)
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting jurisdiction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("jurisdiction"), jurisdiction)

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func allToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

		jurisdictions := model.Jurisdictions{}
		err := jurisdictions.FindAll(ctx, tx)
		if err != nil {
			log.Printf("error querying for jurisdictions: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("jurisdictions"), jurisdictions)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
