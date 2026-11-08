package signedrequest

import (
	"electronic-voting/model"
)

// View is a stored request as it is returned to clients: exactly as it was signed, along with the
// certificate it was signed under, so clients can check its signer. Role, JurisdictionID and CertPEM
// are null if the request didn't need a certificate.
type View struct {
	Action           string                 `json:"action"`
	Instance         string                 `json:"instance"`
	Role             *model.CertificateRole `json:"role"`
	JurisdictionID   *string                `json:"jurisdiction_id"`
	RequestTimestamp string                 `json:"request_timestamp"`
	Body             string                 `json:"body"`
	PublicKey        string                 `json:"public_key"`
	Signature        string                 `json:"signature"`
	CertPEM          *string                `json:"cert_pem"`
}

// ToView converts a model SignedRequest to an object to return to HTTP clients.
func ToView(signedRequest model.SignedRequest) View {
	return View{
		Action:           signedRequest.Action,
		Instance:         signedRequest.Instance,
		Role:             signedRequest.Role,
		JurisdictionID:   signedRequest.JurisdictionID,
		RequestTimestamp: signedRequest.RequestTimestamp,
		Body:             signedRequest.Body,
		PublicKey:        signedRequest.PublicKey,
		Signature:        signedRequest.Signature,
		CertPEM:          signedRequest.CertPEM,
	}
}
