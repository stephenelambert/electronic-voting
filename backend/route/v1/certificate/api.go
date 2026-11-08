package certificate

import (
	"context"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func myToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		account := ctx.Value(ctxkey.Key("account")).(*model.Account)

		if account.SigningKey == nil {
			log.Printf("account missing signing key: %s", account.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		certs := model.Certificates{}
		err := certs.FindActiveByPubPEM(ctx, tx, account.SigningKey.PublicKey)
		if err != nil {
			log.Printf("error getting certificates for user: %s", account.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("certificates"), certs)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
