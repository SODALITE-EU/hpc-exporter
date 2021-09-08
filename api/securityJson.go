package api

type KeycloakResponse struct {
	Email    string `json:"email"`
	Active   bool   `json:"active"`
	Username string `json:"preferred_username"`
}

func newKeycloakResponse() *KeycloakResponse {
	return &KeycloakResponse{
		Email:    "",
		Active:   false,
		Username: "",
	}
}

// TODO Write correct json tags
type VaultSecret struct {
	Password    string `json:"ssh_password"`
	User        string `json:"ssh_user"`
	Private_key string `json:"ssh_pkey"`
	Hpc         string `json:"hpc"`
}

func newVaultSecret() *VaultSecret {
	return &VaultSecret{
		Password:    "",
		User:        "",
		Private_key: "",
		Hpc:         "",
	}
}
