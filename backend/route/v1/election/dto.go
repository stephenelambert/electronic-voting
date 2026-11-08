package election

// keyRequest generates a key for an election that hasn't been created yet. JurisdictionID is the
// jurisdiction in the URL, so the signed request says which jurisdiction the key is for.
type keyRequest struct {
	JurisdictionID string `json:"jurisdiction_id"`
}

type candidateRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// request creates an election. The client generates the IDs, so the signed request covers them,
// and each candidate's ballot position is its index in Candidates. JurisdictionID is the
// jurisdiction in the URL, so the signed request says where the election is. PublicKey is an
// unclaimed key from the election key endpoint and Variant is the blind signature variant it will be
// used with, so the signed request also certifies the key for the election.
type request struct {
	ID             string             `json:"id"`
	JurisdictionID string             `json:"jurisdiction_id"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	TimeOpen       int64              `json:"time_open"`
	TimeClose      int64              `json:"time_close"`
	PublicKey      string             `json:"public_key"`
	Variant        string             `json:"variant"`
	Candidates     []candidateRequest `json:"candidates"`
}
