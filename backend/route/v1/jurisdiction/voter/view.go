package voter

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/signedrequest"
	"log"
	"net/http"
)

// showCertificate writes the certificate in the context to the HTTP response as a newly
// created resource.
func showCertificate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cert := ctx.Value(ctxkey.Key("certificate")).(*model.Certificate)

		if err := lhttp.WriteJSON(w, http.StatusCreated, certificate.ModelCertToView(*cert)); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

type voterView struct {
	Username            string               `json:"username"`
	PublicKey           string               `json:"public_key"`
	AuthorizedTimestamp int64                `json:"authorized_timestamp"`
	Certificate         certificate.CertView `json:"certificate"`
	// Authorization is the admin's signed request that authorized the certificate, which is also
	// published with it (see showAuthorizations)
	Authorization signedrequest.View `json:"authorization"`
}

type votersView struct {
	Total  int         `json:"total"`
	Voters []voterView `json:"voters"`
}

// showVoters writes the page of voters and the total number of voters in the context to the HTTP
// response.
func showVoters() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		voters := ctx.Value(ctxkey.Key("voters")).(model.AccountsWithOneCertificate)
		total := ctx.Value(ctxkey.Key("voters_total")).(int)

		view := votersView{
			Total:  total,
			Voters: make([]voterView, len(voters)),
		}
		for i, voter := range voters {
			cert := *voter.SigningKey.Certificate

			// use not_before rather than creation_timestamp: it is copied from the signed certificate,
			// so it can be checked against cert_pem
			view.Voters[i] = voterView{
				Username:            voter.Username,
				PublicKey:           voter.SigningKey.PublicKey,
				AuthorizedTimestamp: cert.NotBefore,
				Certificate:         certificate.ModelCertToView(cert),
				Authorization:       signedrequest.ToView(*voter.Authorization),
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, view); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// authorizationView is a voter's certificate along with the admin's signed request that authorized
// it. Both name the voter by key, not by username, so authorizations can be published.
type authorizationView struct {
	Certificate   certificate.CertView `json:"certificate"`
	Authorization signedrequest.View   `json:"authorization"`
}

// showAuthorizations writes the voter authorizations in the context to the HTTP response as a JSON
// array
func showAuthorizations() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		authorizations := ctx.Value(ctxkey.Key("voter_authorizations")).(model.AuthorizedCertificates)
		views := make([]authorizationView, len(authorizations))
		for i, authorization := range authorizations {
			views[i] = authorizationView{
				Certificate:   certificate.ModelCertToView(authorization.Certificate),
				Authorization: signedrequest.ToView(authorization.Authorization),
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, views); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
