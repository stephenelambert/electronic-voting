package voter

// request authorizes the account with the public key to vote in a jurisdiction. JurisdictionID is
// the jurisdiction in the URL, so the signed request says where the voter was authorized.
type request struct {
	JurisdictionID string `json:"jurisdiction_id"`
	PublicKey      string `json:"public_key"`
}
