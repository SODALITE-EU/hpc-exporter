package api

import (
	"encoding/json"
	"errors"
	"hpc_exporter/conf"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type UserData struct {
	username        string
	email           string
	jwt             string
	ssh_private_key string
	ssh_password    string
	ssh_user        string
}

func NewUserData() *UserData {
	return &UserData{
		username:        "",
		email:           "",
		jwt:             "",
		ssh_private_key: "",
		ssh_password:    "",
		ssh_user:        "",
	}
}

func (d *UserData) getJWT(r *http.Request) error {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) != 2 {
		return errors.New("incorrect authorization header format")
	}
	d.jwt = strings.TrimSpace(splitToken[1])
	return nil
}

func (d *UserData) GetUser(r *http.Request, security_conf conf.Security) error {
	if d.jwt == "" {
		if err := d.getJWT(r); err != nil {
			return err
		}
	}
	client := &http.Client{}

	data := url.Values{}
	data.Set("token", d.jwt)

	req, err := http.NewRequest("POST", security_conf.Introspection_endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return errors.New("could not create authentication request")
	}

	req.SetBasicAuth(security_conf.Introspection_client, security_conf.Introspection_secret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("there was an error trying to reach the Keycloak server")
	}

	ok := resp.StatusCode == 200

	keycloak_response := newKeycloakResponse()
	if err := json.NewDecoder(resp.Body).Decode(keycloak_response); err != nil {

	} else if !ok || !keycloak_response.Active {
		return errors.New("Unauthorized")
	}
	d.email = keycloak_response.Email
	d.username = keycloak_response.Username
	return nil

}

func (d *UserData) GetSSHCredentials(hpc string, r *http.Request, security_conf conf.Security) error {
	if d.jwt == "" {
		d.getJWT(r)
	}

	client := &http.Client{}

	secret_endpoint := "http://" + security_conf.Vault_secret_uploader_address + "/ssh/" + hpc
	req, err := http.NewRequest("GET", secret_endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.jwt)
	resp_vault, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp_vault.Body.Close()
	vault_secret := newVaultSecret()
	if err := json.NewDecoder(resp_vault.Body).Decode(vault_secret); err != nil {
		return errors.New("error when retrieving the Vault secrets")
	}
	d.ssh_user = vault_secret.User
	if d.ssh_user == "" {
		return errors.New("no user stored in Vault")
	}
	d.ssh_password = vault_secret.Password
	d.ssh_private_key = vault_secret.Private_key
	return nil
}
