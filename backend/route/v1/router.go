package v1

import (
	"electronic-voting/route/v1/account"
	"electronic-voting/route/v1/certificate"
	"electronic-voting/route/v1/election"
	"electronic-voting/route/v1/jurisdiction"
	"electronic-voting/route/v1/login"
	"electronic-voting/route/v1/register"

	"github.com/gorilla/mux"
)

// Router returns a subrouter for the parent router with the path "v1"
func Router(r *mux.Router) {
	sub := r.PathPrefix("/v1").Subrouter()

	account.Router(sub)
	certificate.Router(sub)
	login.Router(sub)
	register.Router(sub)
	jurisdiction.Router(sub)
	election.Router(sub)
}
