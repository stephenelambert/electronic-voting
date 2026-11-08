package certificate

import (
	"net/http"

	lhttp "electronic-voting/http"

	"github.com/gorilla/mux"
)

func Router(r *mux.Router) {
	sub := r.PathPrefix("/certificates").Subrouter()

	// the root signs every other certificate, and clients hash its key for the instance their signed
	// requests name
	sub.Methods(http.MethodGet).Path("/root").
		Handler(showRoot())

	c := sub.PathPrefix("/my").Subrouter()

	c.Methods(http.MethodGet).Path("").
		Handler(lhttp.AuthenticateRequest(
			"certificate.list_own",
			nil,
			nil,
			myToCtx(showCertificates())))
}
