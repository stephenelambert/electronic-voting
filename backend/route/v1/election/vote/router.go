package vote

import (
	"net/http"

	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ptr"

	"github.com/gorilla/mux"
)

// Router adds the routes for voting in an election to the given election router, which must put the
// election into the request context.
func Router(e *mux.Router) {
	// reading a record only needs the account's signature, not a current voter certificate, so
	// voters can still check past votes after they are deauthorized. It can't be used to vote
	e.Methods(http.MethodGet).Path("/recovery-record").
		Handler(lhttp.AuthenticateRequest(
			"recovery_record.read",
			nil,
			nil,
			recoveryRecordToCtx(showRecoveryRecord(http.StatusOK))))

	e.Methods(http.MethodPost).Path("/recovery-record").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"recovery_record.create",
				ptr.Of(model.CertificateVoterRole),
				electionJurisdiction,
				lhttp.CanonicalDtoToCtx[recoveryRecordRequest]("dto",
					createRecoveryRecord(showRecoveryRecord(http.StatusCreated), showRecoveryRecord(http.StatusOK))))))

	e.Methods(http.MethodPost).Path("/blind-signatures").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"blind_signature.request",
				ptr.Of(model.CertificateVoterRole),
				electionJurisdiction,
				lhttp.CanonicalDtoToCtx[blindSignatureRequest]("dto",
					blindSign(showBlindSignature(http.StatusCreated), showBlindSignature(http.StatusOK))))))

	// votes aren't authenticated, so casting one isn't directly tied to the voter's account, but
	// the server can link the two through the authenticated requests around it, like the one for
	// the blind signature
	e.Methods(http.MethodPost).Path("/votes").
		Handler(lhttp.BodyToCtx(
			lhttp.DtoToCtx[castRequest]("dto",
				cast(showStatus(http.StatusCreated), showStatus(http.StatusOK)))))

	// these three can freeze the election's counter once it closes, which is when its votes are
	// published
	e.Methods(http.MethodGet).Path("/votes/summary").
		Handler(summarize(showSummary()))

	e.Methods(http.MethodGet).Path("/votes/published").
		Handler(publishedToCtx(showPublishedVotes()))

	// the voters' requests for blind signatures are published with the votes, so auditors can check
	// that the votes don't outnumber the authorized voters who asked for signatures
	e.Methods(http.MethodGet).Path("/blind-signature-requests").
		Handler(blindSignatureRequestsToCtx(showBlindSignatureRequests()))

	// publishing the results builds the election's hash tree, which proofs are served from
	e.Methods(http.MethodPost).Path("/results").
		Handler(lhttp.BodyToCtx(
			lhttp.AuthenticateRequest(
				"results.publish",
				ptr.Of(model.CertificateGlobalAdminRole),
				nil,
				lhttp.CanonicalDtoToCtx[resultsRequest]("dto",
					publishResults(showResults(http.StatusCreated), showResults(http.StatusOK))))))

	e.Methods(http.MethodGet).Path("/results").
		Handler(resultsToCtx(showPublishedResults()))

	// proofs aren't authenticated, so asking for one isn't directly tied to the voter's account,
	// but the server can link the two through the authenticated requests around it, like the one
	// for the voter's recovery record
	e.Methods(http.MethodGet).Path("/votes/{nonce:[0-9a-f]{64}}/proof").
		Handler(proofToCtx(showProof()))
}
