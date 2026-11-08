package voter

import (
	"net/http"

	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ptr"

	"github.com/gorilla/mux"
)

// Router adds voter routes to the given jurisdiction router, which must put the
// jurisdiction into the request context.
func Router(j *mux.Router) {
	j.Methods(http.MethodPost).Path("/voters").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"voter.authorize",
				ptr.Of(model.CertificateGlobalAdminRole),
				nil,
				lhttp.CanonicalDtoToCtx[request]("dto", authorize(showCertificate())))))

	j.Methods(http.MethodGet).Path("/voters").
		Handler(lhttp.AuthenticateRequest(
			"voter.list",
			ptr.Of(model.CertificateGlobalAdminRole),
			nil,
			allToCtx(showVoters())))

	// every voter authorization is published, naming voters by key rather than username, so anyone
	// can count the jurisdiction's voters and check that an admin authorized each one
	j.Methods(http.MethodGet).Path("/voter-authorizations").
		Handler(authorizationsToCtx(showAuthorizations()))
}
