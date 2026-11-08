package login

// startRequest begins an OPAQUE login with the client's KE1
type startRequest struct {
	Username string `json:"username"`
	KE1      string `json:"ke1"`
}

// request finishes the login started as login_id with the client's KE3
type request struct {
	LoginID string `json:"login_id"`
	KE3     string `json:"ke3"`
}
