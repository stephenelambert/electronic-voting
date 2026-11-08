package election

import (
	"context"
	"electronic-voting/database"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/dbcrypt"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// minCandidates is the fewest candidates an election can have
const minCandidates = 2

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

		election := model.Election{
			ID: id,
		}

		found, err := election.FindByID(ctx, tx)
		if err != nil {
			log.Printf("error querying for election: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("election"), election)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// signedRequestToCtx finds the signed request that created the election in the context. toCtx leaves
// it out, so only the routes that show it query for it, and voting does no extra work.
func signedRequestToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		if err := election.FindSignedRequest(ctx, tx); err != nil {
			log.Printf("error querying for signed request that created election: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("election"), election)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validate returns why the request to create an election in the jurisdiction is invalid, or "" if
// it is valid. now is the current Unix time.
func validate(req *request, jurisdictionID string, now int64) string {
	if !localcrypto.UUIDIsCanonical(req.ID) {
		return "election id is not a canonical uuid"
	}
	if req.JurisdictionID != jurisdictionID {
		return "election is for a different jurisdiction"
	}
	if strings.TrimSpace(req.Title) == "" {
		return "title is blank"
	}
	if req.TimeOpen <= now {
		return "election doesn't open in the future"
	}
	if req.TimeClose <= req.TimeOpen {
		return "election doesn't close after it opens"
	}
	if req.Variant != localcrypto.ElectionKeyVariant {
		return "election key variant is not supported"
	}
	if len(req.Candidates) < minCandidates {
		return fmt.Sprintf("election has fewer than %d candidates", minCandidates)
	}

	candidateIDs := make(map[string]bool, len(req.Candidates))
	for _, candidate := range req.Candidates {
		if !localcrypto.UUIDIsCanonical(candidate.ID) {
			return "candidate id is not a canonical uuid"
		}
		if candidateIDs[candidate.ID] {
			return "candidate ids are not unique"
		}
		candidateIDs[candidate.ID] = true

		if strings.TrimSpace(candidate.Name) == "" {
			return "candidate name is blank"
		}
	}

	return ""
}

// createKey generates a key for an election that hasn't been created yet in the jurisdiction in the
// context. The key has no owner until a request to create an election claims it with its public key.
func createKey(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)
		req := ctx.Value(ctxkey.Key("dto")).(*keyRequest)

		// the signed request says which jurisdiction the key is for, so it has to be this one
		if req.JurisdictionID != jurisdiction.ID {
			log.Print("request for an election key is for a different jurisdiction")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		privateKeyPEM, publicKeyPEM, err := localcrypto.GenerateElectionKey()
		if err != nil {
			log.Printf("error generating election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		signingKey := model.SigningKey{
			PrivateKey:        dbcrypt.EncryptedString(privateKeyPEM),
			PublicKey:         publicKeyPEM,
			OwnerType:         model.KeyElectionOwner,
			CreationTimestamp: time.Now().Unix(),
		}
		if err = signingKey.DbInsert(ctx, tx); err != nil {
			log.Printf("error inserting election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("signing_key"), signingKey)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// create creates an election with its candidates in the jurisdiction in the context. It claims the
// election key with the public key in the request, which must come from createKey and not belong to
// an election yet. The request's signature covers the public key, so the signed request, which is
// stored with the election, is what certifies the key for the election.
func create(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*request)

		now := time.Now().Unix()

		if reason := validate(req, jurisdiction.ID, now); reason != "" {
			log.Printf("invalid request to create election: %s", reason)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// the key must already be in normalized form, which is how the key endpoint returns it, so
		// the stored key is identical to the signed one (like ids, which must be canonical)
		publicKey, _, err := localcrypto.NormalizePublicKeyPEM(req.PublicKey)
		if err != nil {
			log.Printf("invalid public key in request to create election: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if publicKey != req.PublicKey {
			log.Print("public key in request to create election is not in normalized form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		signingKey := model.SigningKey{
			PublicKey: publicKey,
		}
		claimed, err := signingKey.ClaimElectionKey(ctx, tx, req.ID)
		if err != nil {
			log.Printf("error claiming election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !claimed {
			// the key is unknown or already claimed. if the election exists, this repeats the
			// request that created it and claimed the key (claiming waits for a concurrent claim of
			// the key to commit, so its election is visible here)
			existing := model.Election{
				ID: req.ID,
			}
			var found bool
			found, err = existing.FindByID(ctx, tx)
			if err != nil {
				log.Printf("error querying for existing election: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if found {
				log.Printf("election %s already exists", req.ID)
				w.WriteHeader(http.StatusConflict)
				return
			}

			log.Print("public key in request to create election is not an unclaimed election key")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// values are stored exactly as sent (not trimmed), so they match the request the client
		// signed
		election := model.Election{
			ID:               req.ID,
			JurisdictionID:   jurisdiction.ID,
			Title:            req.Title,
			Description:      req.Description,
			TimeOpen:         req.TimeOpen,
			TimeClose:        req.TimeClose,
			PublicKey:        signingKey.PublicKey,
			CreatedTimestamp: now,
			Candidates:       make([]model.Candidate, len(req.Candidates)),
			SignedRequest:    signedRequest,
		}
		for i, candidate := range req.Candidates {
			election.Candidates[i] = model.Candidate{
				ID:          candidate.ID,
				Position:    i,
				Name:        candidate.Name,
				Description: candidate.Description,
			}
		}

		err = election.DBInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			log.Printf("election %s or one of its candidates already exists", req.ID)
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting election: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("election"), election)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// allToCtx adds the elections for the jurisdiction in the context to the context, most recent
// first.
func allToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)

		elections := model.Elections{}
		err := elections.FindByJurisdiction(ctx, tx, jurisdiction.ID)
		if err != nil {
			log.Printf("error querying for elections: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("elections"), elections)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
