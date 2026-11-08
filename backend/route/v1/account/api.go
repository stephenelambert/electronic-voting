package account

import (
	"context"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// searchLimit is the maximum number of accounts returned by a search
const searchLimit = 25

// searchToCtx finds accounts whose usernames start with the "username" query parameter and
// adds them to the context.
func searchToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

		// require a search term, so the endpoint can't list every account
		username := r.URL.Query().Get("username")
		if username == "" {
			log.Print("missing username query parameter in account search")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		accounts := model.Accounts{}
		err := accounts.SearchByUsernamePrefix(ctx, tx, username, searchLimit)
		if err != nil {
			log.Printf("error searching for accounts: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("accounts"), accounts)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
