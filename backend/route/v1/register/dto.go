package register

// startRequest begins an OPAQUE registration
type startRequest struct {
	Username            string `json:"username"`
	RegistrationRequest string `json:"registration_request"`
}

type request struct {
	Username           string `json:"username"`
	RegistrationRecord string `json:"registration_record"`
	PublicKey          string `json:"public_key"`
	PrivateKey         string `json:"private_key"`
	// RegistrationToken claims an admin account the API created, as its setup token
	RegistrationToken *string `json:"registration_token"`
	AesKey            string  `json:"aes_key"`
}
