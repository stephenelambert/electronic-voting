package account

import (
	"net/http"

	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ptr"

	"github.com/gorilla/mux"
)

func Router(r *mux.Router) {
	sub := r.PathPrefix("/accounts").Subrouter()

	sub.Methods(http.MethodGet).Path("").
		Handler(lhttp.AuthenticateRequest(
			"account.search",
			ptr.Of(model.CertificateGlobalAdminRole),
			nil,
			searchToCtx(showAccounts())))
}
