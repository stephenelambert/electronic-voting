package certificate

import (
	lhttp "electronic-voting/http"
	"electronic-voting/localsigner"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"
)

// showCertificates takes the certificates in the context and writes them to the HTTP response
// as a JSON array.
func showCertificates() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		certificates := ctx.Value(ctxkey.Key("certificates")).(model.Certificates)
		certViews := make([]certificate.CertView, len(certificates))
		for i, cert := range certificates {
			certViews[i] = certificate.ModelCertToView(cert)
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, certViews); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// rootView is the root certificate, which signs every other certificate, and its public key.
// Clients hash the key for the instance their signed requests name, so signing doesn't need to parse
// the certificate.
type rootView struct {
	CertPEM   string `json:"cert_pem"`
	PublicKey string `json:"public_key"`
}

// showRoot writes the root certificate to the HTTP response
func showRoot() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root := localsigner.GetCert()

		view := rootView{
			CertPEM:   root.CertPEM,
			PublicKey: root.PubPEM,
		}
		if err := lhttp.WriteJSON(w, http.StatusOK, view); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
