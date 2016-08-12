package vaultclient

import (
	"fmt"
	"log"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type VaultClient interface {
	Run()
	Stop()
	DeriveToken() (string, error)
	GetConsulACL() (string, error)
	RenewToken(token string) <-chan error
}

type DefaultVaultClient struct {
	PeriodicToken  string
	vaultAPIClient *vaultapi.Client
	ShutdownCh     chan bool
}

func (vc *DefaultVaultClient) Run() {
	for {
		select {
		case <-vc.ShutdownCh:
			log.Printf("Run() method returning~~~~~~~~")
			return
		}
	}
}

func (vc *DefaultVaultClient) Stop() {
	derivedWrappedToken, err := vc.DeriveToken()
	if err != nil {
		log.Printf("failed to derive a vault token: %v", err)
	}

	log.Printf("vaultclient: Derived wrapped vault token: %s", derivedWrappedToken)

	vc.RenewToken(derivedWrappedToken)

	time.Sleep(3 * time.Second)

	vc.ShutdownCh <- true
}

func (vc *DefaultVaultClient) DeriveToken() (string, error) {
	tcr := &vaultapi.TokenCreateRequest{
		ID:          "vault-token-123",
		Policies:    []string{"foo", "bar"},
		TTL:         "10h",
		DisplayName: "derived-token",
		Renewable:   new(bool),
	}
	*tcr.Renewable = true

	client, err := vc.getVaultAPIClient()
	if err != nil {
		return "", fmt.Errorf("failed to create vault API client: %v", err)
	}

	wrapLookupFunc := func(method, path string) string {
		if method == "POST" && path == "auth/token/create" {
			return "60s"
		}
		return ""
	}
	client.SetWrappingLookupFunc(wrapLookupFunc)

	secret, err := client.Auth().Token().Create(tcr)
	if err != nil {
		return "", fmt.Errorf("failed to create vault token: %v", err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" ||
		secret.WrapInfo.WrappedAccessor == "" {
		return "", fmt.Errorf("failed to derive a wrapped vault token")
	}

	return secret.WrapInfo.Token, nil
}

func (vc *DefaultVaultClient) GetConsulACL() (string, error) {
	return "", nil
}

func (vc *DefaultVaultClient) RenewToken(wrappedToken string) <-chan error {
	client, err := vc.getVaultAPIClient()
	if err != nil {
		log.Printf("failed to create vault API client: %v", err)
	}

	unwrapResp, err := client.Logical().Unwrap(wrappedToken)
	if err != nil {
		log.Printf("failed to unwrap the token: %v", err)
	}
	if unwrapResp == nil || unwrapResp.Auth == nil || unwrapResp.Auth.ClientToken == "" {
		log.Printf("failed to unwrap the token")
	}

	log.Printf("unwrapped token: %s\n", unwrapResp.Auth.ClientToken)

	renewResp, err := client.Auth().Token().Renew(unwrapResp.Auth.ClientToken, 0)
	if err != nil {
		log.Printf("failed to renew the vault token: %v", err)
	}
	if renewResp == nil || renewResp.Auth == nil {
		log.Printf("failed to renew the vault token")
	}
	log.Printf("renewResp: %#v\n", renewResp)

	//TODO: Should an error channel be returned or should the renewal error
	//be sent over a channel?
	var errCh chan error
	return errCh
}

func (vc *DefaultVaultClient) getVaultAPIClient() (*vaultapi.Client, error) {
	if vc.vaultAPIClient == nil {
		// Get the default configuration
		config := vaultapi.DefaultConfig()

		// Read the environment variables and update the configuration
		if err := config.ReadEnvironment(); err != nil {
			return nil, fmt.Errorf("failed to read the environment: %v", err)
		}

		// Create a Vault API Client
		client, err := vaultapi.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %v", err)
		}

		// Set the authentication required
		client.SetToken(vc.PeriodicToken)
		vc.vaultAPIClient = client
	}

	return vc.vaultAPIClient, nil
}
