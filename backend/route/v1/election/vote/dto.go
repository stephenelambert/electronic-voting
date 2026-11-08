package vote

// recoveryRecordRequest uploads the voter's recovery record for an election. ElectionID is the
// election in the URL, so the signed request says which election the record is for.
// EncryptedRecord is base64, and only the voter's client can decrypt it.
type recoveryRecordRequest struct {
	ElectionID      string `json:"election_id"`
	EncryptedRecord string `json:"encrypted_record"`
}

// blindSignatureRequest asks for the election key's signature on a blinded vote, which is base64.
// ElectionID is the election in the URL, so the signed request says which election the vote is for.
// PublicKeyHash is the base64 SHA-256 hash of the DER encoding of the key the voter blinded the vote
// under, so the signed request records which key that was.
type blindSignatureRequest struct {
	ElectionID     string `json:"election_id"`
	BlindedMessage string `json:"blinded_message"`
	PublicKeyHash  string `json:"public_key_hash"`
}

// castRequest casts a vote. Nonce is the 32 random bytes RFC 9474 adds to the front of the vote, as
// lowercase hex, Vote is the vote JSON exactly as signed, and Signature is the election key's
// signature over the nonce followed by the vote, as base64.
type castRequest struct {
	Nonce     string `json:"nonce"`
	Vote      string `json:"vote"`
	Signature string `json:"signature"`
}

// resultsRequest publishes an election's results: how many votes it has, the root of its hash tree
// (base64), and its tally, which is the root's counts, exactly as hashed. It
// must be in canonical form (see localcrypto.CanonicalJSON), so the signed request means the same
// thing to every JSON parser.
type resultsRequest struct {
	ElectionID string `json:"election_id"`
	VoteCount  int64  `json:"vote_count"`
	RootHash   string `json:"root_hash"`
	Tally      string `json:"tally"`
}
