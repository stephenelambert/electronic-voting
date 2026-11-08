package login

import (
	"context"
	lhttp "electronic-voting/http"
	"electronic-voting/localopaque"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// startLogin answers the client's KE1 with KE2, and keeps the MAC its KE3 must hold until login
// finishes it
func startLogin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		dto := ctx.Value(ctxkey.Key("dto")).(*startRequest)

		now := time.Now().Unix()

		// clean up the logins that expired before they finished
		if err := model.DeletePendingLoginsBefore(ctx, tx, now-localopaque.PendingLoginLifetime); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// an account the API created and nobody has registered yet is treated like a missing one, so
		// it isn't told apart from one
		account := &model.Account{
			Username: dto.Username,
		}
		if found, err := account.FindByUsername(ctx, tx); err != nil {
			log.Printf("error selecting account for login: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found || account.OpaqueRecord == nil {
			log.Printf("user %s not found or not registered", account.Username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ke2, expectedClientMAC, err := localopaque.StartLogin(account.Username, account.OpaqueRecord, dto.KE1)
		if errors.Is(err, localopaque.ErrInvalidMessage) {
			log.Printf("invalid OPAQUE KE1: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("error answering OPAQUE KE1: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		pending := &model.PendingLogin{
			AccountID:         account.ID,
			ExpectedClientMAC: expectedClientMAC,
			CreationTimestamp: now,
		}
		if err = pending.DbInsert(ctx, tx); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		view := struct {
			LoginID string `json:"login_id"`
			KE2     string `json:"ke2"`
		}{
			LoginID: pending.ID,
			KE2:     ke2,
		}
		if err := lhttp.WriteJSON(w, http.StatusOK, view); err != nil {
			log.Printf("error writing json to response: %s", err.Error())
		}
	})
}

// login finishes a login with the client's KE3, which shows it knows the account's password, before
// handing over the account's encrypted keys
func login(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		dto := ctx.Value(ctxkey.Key("dto")).(*request)

		if err := uuid.Validate(dto.LoginID); err != nil {
			log.Printf("invalid login ID: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// each pending login is only used once. A failed check below rolls the delete back with the
		// rest of the request, so the login can be tried again until it expires, but a KE3 can't be
		// guessed
		pending := &model.PendingLogin{
			ID: dto.LoginID,
		}
		username, found, err := pending.Take(ctx, tx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found {
			log.Print("pending login not found")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if pending.CreationTimestamp < time.Now().Unix()-localopaque.PendingLoginLifetime {
			log.Print("pending login expired")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err = localopaque.FinishLogin(dto.KE3, pending.ExpectedClientMAC); err != nil {
			log.Printf("invalid OPAQUE KE3: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		account := &model.Account{
			Username: username,
		}
		if found, err := account.FindByUsername(ctx, tx); err != nil {
			log.Printf("error selecting account for login: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found {
			log.Printf("user %s not found", account.Username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// an account without an active signing key can't do anything, since requests are signed with it
		if account.SigningKey == nil {
			log.Printf("user (%s) does not have signing key", account.Username)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// fetch certificates for the user
		certificates := model.Certificates{}
		err = certificates.FindActiveByPubPEM(ctx, tx, account.SigningKey.PublicKey)
		if err != nil {
			log.Printf("error fetching user certificates on login: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("account"), account)
		ctx = context.WithValue(ctx, ctxkey.Key("certificates"), certificates)

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
