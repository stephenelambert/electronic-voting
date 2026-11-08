package election

import (
	"net/http"

	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/route/v1/election/vote"
	"electronic-voting/util/ptr"

	"github.com/gorilla/mux"
)

// JurisdictionRouter adds the routes for a jurisdiction's elections to the given jurisdiction
// router, which must put the jurisdiction into the request context.
func JurisdictionRouter(j *mux.Router) {
	j.Methods(http.MethodPost).Path("/election-keys").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"election_key.create",
				ptr.Of(model.CertificateGlobalAdminRole),
				nil,
				lhttp.CanonicalDtoToCtx[keyRequest]("dto", createKey(showKey(http.StatusCreated))))))

	j.Methods(http.MethodPost).Path("/elections").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"election.create",
				ptr.Of(model.CertificateGlobalAdminRole),
				nil,
				lhttp.CanonicalDtoToCtx[request]("dto", create(showElection(http.StatusCreated))))))

	j.Methods(http.MethodGet).Path("/elections").
		Handler(allToCtx(showElections()))
}

// Router adds the routes for single elections, at "/elections/{id}", to the given router
func Router(r *mux.Router) {
	sub := r.PathPrefix("/elections").Subrouter()

	e := sub.PathPrefix("/{id}").Subrouter()
	e.Use(toCtx)

	e.Methods(http.MethodGet).Path("").
		Handler(signedRequestToCtx(showElection(http.StatusOK)))

	vote.Router(e)
}
