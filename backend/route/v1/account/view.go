package account

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"
)

type accountView struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

func toView(account model.Account) accountView {
	view := accountView{
		Username: account.Username,
	}

	if account.SigningKey != nil {
		view.PublicKey = account.SigningKey.PublicKey
	}

	return view
}

// showAccounts takes the accounts in the context and writes them to the HTTP response
// as a JSON array.
func showAccounts() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accounts := ctx.Value(ctxkey.Key("accounts")).(model.Accounts)
		views := make([]accountView, len(accounts))
		for i, account := range accounts {
			views[i] = toView(account)
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, views); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
