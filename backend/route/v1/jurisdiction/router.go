package jurisdiction

import (
	"net/http"

	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/route/v1/election"
	"electronic-voting/route/v1/jurisdiction/voter"
	"electronic-voting/util/ptr"

	"github.com/gorilla/mux"
)

func Router(r *mux.Router) {
	sub := r.PathPrefix("/jurisdictions").Subrouter()

	sub.Methods(http.MethodPost).Path("").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"jurisdiction.create",
				ptr.Of(model.CertificateGlobalAdminRole),
				nil,
				lhttp.CanonicalDtoToCtx[request]("dto", create(showJurisdiction())))))

	sub.Methods(http.MethodGet).Path("").
		Handler(allToCtx(showJurisdictions()))

	j := sub.PathPrefix("/{id}").Subrouter()
	j.Use(toCtx)

	j.Methods(http.MethodGet).Path("").
		Handler(signedRequestToCtx(showJurisdiction()))

	voter.Router(j)
	election.JurisdictionRouter(j)
}
