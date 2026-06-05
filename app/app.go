// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	gkms "cloud.google.com/go/kms/apiv1"
	gsecretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gittuf/github-app/internal/webhook"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kelseyhightower/envconfig"
	"github.com/octo-sts/app/pkg/gcpkms"
	"golang.org/x/crypto/ssh"
)

const (
	cloudProviderAWS = "aws"
	cloudProviderGCP = "gcp"
)

var ErrNotImplemented = errors.New("this functionality is not implemented yet")

func Execute() {
	/*
		This is heavily inspired by the webhook in
		https://github.com/chainguard-dev/octo-sts written by @wlynch.
	*/

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var env webhook.EnvConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Panicf("unable to process environment variables: %s", err.Error())
	}

	log.Default().Println("Processed env vars")

	var infraProvider provider
	if env.DevMode {
		switch env.AppSigningMethod {
		case "ssh":
			infraProvider = &devModeSSHProvider{env: &env}
		case "gpg":
			infraProvider = &devModeGPGProvider{env: &env}
		default:
			log.Panicf("unsupported app signing method '%s'", env.AppSigningMethod)
		}
	} else {
		switch env.CloudProvider {
		case cloudProviderAWS:
			infraProvider = &awsProvider{env: &env}
		case cloudProviderGCP:
			infraProvider = &gcpProvider{env: &env}
		default:
			log.Panicf("unsupported cloud provider '%s'", env.CloudProvider)
		}
	}

	if err := infraProvider.PrepareGitSigningKey(ctx); err != nil {
		log.Panicf("error preparing git signing key: %v", err)
	}

	signer, err := infraProvider.GetTransportSigner(ctx)
	if err != nil {
		log.Panicf("error configuring signer for ghinstallation transport: %v", err)
	}
	transport, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, env.AppID, ghinstallation.WithSigner(signer))
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}
	if env.GitHubURL != webhook.DefaultGitHubURL {
		transport.BaseURL = fmt.Sprintf("%s/%s/%s/", env.GitHubURL, "api", "v3")
	}

	webhookSecrets, err := infraProvider.GetWebhookSecrets(ctx)
	if err != nil {
		log.Panicf("error fetching webhook secrets: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", &webhook.GittufApp{
		Transport:     transport,
		WebhookSecret: webhookSecrets,
		Params:        &env,
	})

	log.Default().Println("Serving...")
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", env.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
	}
	log.Panic(srv.ListenAndServe())
}

type provider interface {
	GetWebhookSecrets(context.Context) ([][]byte, error)
	PrepareGitSigningKey(context.Context) error
	GetTransportSigner(context.Context) (ghinstallation.Signer, error)
}

type devModeSSHProvider struct {
	env *webhook.EnvConfig
}

func (p *devModeSSHProvider) GetWebhookSecrets(_ context.Context) ([][]byte, error) {
	return [][]byte{[]byte(p.env.WebhookSecret)}, nil
}

func (p *devModeSSHProvider) PrepareGitSigningKey(_ context.Context) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("unable to identify user's home directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0o755); err != nil {
		return fmt.Errorf("unable to create .ssh directory: %v", err)
	}
	privateKeyPath := filepath.Join(homeDir, ".ssh", webhook.KeyFileName)

	privkeyBytes, err := os.ReadFile(p.env.AppSigningKey)
	if err != nil {
		return fmt.Errorf("error reading app signing key: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, privkeyBytes, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("error writing app signing key: %v", err)
	}

	pubkeyBytes, err := os.ReadFile(p.env.AppSigningPubKey)
	if err != nil {
		return fmt.Errorf("error reading app public key: %v", err)
	}
	pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if err := os.WriteFile(pubkeyPath, pubkeyBytes, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("error writing app public key: %v", err)
	}

	return nil
}

func (p *devModeSSHProvider) GetTransportSigner(_ context.Context) (ghinstallation.Signer, error) {
	keyBytes, err := os.ReadFile(p.env.KMSKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read signing key: %v", err)
	}

	_, rawKey, err := decodeAndParsePEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signing key: %v", err)
	}

	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, must be RSA")
	}

	return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
}

type devModeGPGProvider struct {
	env *webhook.EnvConfig
}

func (p *devModeGPGProvider) GetWebhookSecrets(_ context.Context) ([][]byte, error) {
	return [][]byte{[]byte(p.env.WebhookSecret)}, nil
}

func (p *devModeGPGProvider) PrepareGitSigningKey(_ context.Context) error {
	// In Dev mode + GPG, we assume env.AppSigningKey contains the armored
	// private key which we must import into the default GPG keyring for Git to
	// use. We just rely on the standard gpg binary to handle everything for us.

	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = bytes.NewReader([]byte(p.env.AppSigningKey))

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error importing GPG key: %v, output: %s", err, string(output))
	}

	return nil
}

func (p *devModeGPGProvider) GetTransportSigner(_ context.Context) (ghinstallation.Signer, error) {
	keyBytes, err := os.ReadFile(p.env.KMSKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read signing key: %v", err)
	}

	_, rawKey, err := decodeAndParsePEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signing key: %v", err)
	}

	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, must be RSA")
	}

	return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
}

type gcpProvider struct {
	env           *webhook.EnvConfig
	secretManager *gsecretmanager.Client
}

func (p *gcpProvider) getSecretManagerClient(ctx context.Context) (*gsecretmanager.Client, error) {
	if p.secretManager != nil {
		return p.secretManager, nil
	}

	secretManager, err := gsecretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create secret manager client: %v", err)
	}

	p.secretManager = secretManager
	return p.secretManager, nil
}

func (p *gcpProvider) GetWebhookSecrets(ctx context.Context) ([][]byte, error) {
	secretmanager, err := p.getSecretManagerClient(ctx)
	if err != nil {
		return nil, err
	}

	webhookSecrets := [][]byte{}
	for _, name := range strings.Split(p.env.WebhookSecret, ",") {
		resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: name,
		})
		if err != nil {
			return nil, fmt.Errorf("error fetching webhook secret %s: %v", name, err)
		}
		webhookSecrets = append(webhookSecrets, resp.GetPayload().GetData())
	}

	return webhookSecrets, nil
}

func (p *gcpProvider) PrepareGitSigningKey(ctx context.Context) error {
	secretmanager, err := p.getSecretManagerClient(ctx)
	if err != nil {
		return err
	}

	resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: p.env.AppSigningKey,
	})
	if err != nil {
		return fmt.Errorf("error fetching signing key: %v", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("unable to identify user's home directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0o755); err != nil {
		return fmt.Errorf("unable to create .ssh directory: %v", err)
	}
	privateKeyPath := filepath.Join(homeDir, ".ssh", webhook.KeyFileName)

	if err := os.WriteFile(privateKeyPath, resp.GetPayload().GetData(), 0o600); err != nil {
		return fmt.Errorf("unable to write private key; %v", err)
	}

	resp, err = secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: p.env.AppSigningPubKey,
	})
	if err != nil {
		return fmt.Errorf("error fetching public key: %v", err)
	}

	pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if err := os.WriteFile(pubkeyPath, resp.GetPayload().GetData(), 0o600); err != nil {
		return fmt.Errorf("unable to write public key; %v", err)
	}

	return nil
}

func (p *gcpProvider) GetTransportSigner(ctx context.Context) (ghinstallation.Signer, error) {
	kms, err := gkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create kms client: %v", err)
	}
	return gcpkms.New(ctx, kms, p.env.KMSKey)
}

type awsProvider struct {
	env *webhook.EnvConfig
}

func (p *awsProvider) GetWebhookSecrets(_ context.Context) ([][]byte, error) {
	return nil, ErrNotImplemented
}

func (p *awsProvider) PrepareGitSigningKey(_ context.Context) error {
	return ErrNotImplemented
}

func (p *awsProvider) GetTransportSigner(_ context.Context) (ghinstallation.Signer, error) {
	return nil, ErrNotImplemented
}

// This entire section needs to go once we hook this up with a secrets manager.

var (
	// ErrNoPEMBlock gets triggered when there is no PEM block in the provided file
	ErrNoPEMBlock = errors.New("failed to decode the data as PEM block (are you sure this is a pem file?)")
	// ErrFailedPEMParsing gets returned when PKCS1, PKCS8 or PKIX key parsing fails
	ErrFailedPEMParsing = errors.New("failed parsing the PEM block: unsupported PEM type")
	// ErrUnknownKeyType gets returned when we can't recognize the key type
	ErrUnknownKeyType = errors.New("unknown key type")
)

/*
decodeAndParsePEM receives potential PEM bytes decodes them via pem.Decode
and pushes them to parseKey. If any error occurs during this process,
the function will return nil and an error (either ErrFailedPEMParsing
or ErrNoPEMBlock). On success it will return the decoded pemData, the
key object interface and nil as error. We need the decoded pemData,
because LoadKey relies on decoded pemData for operating system
interoperability.
*/
func decodeAndParsePEM(pemBytes []byte) (*pem.Block, any, error) {
	// pem.Decode returns the parsed pem block and a rest.
	// The rest is everything, that could not be parsed as PEM block.
	// Therefore we can drop this via using the blank identifier "_"
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, nil, ErrNoPEMBlock
	}

	// Try to load private key, if this fails try to load
	// key as public key
	key, err := parsePEMKey(data.Bytes)
	if err == nil {
		return data, key, nil
	}

	// Try to parse SSH private key
	key, err = ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		return data, key, nil
	}

	return nil, nil, ErrUnknownKeyType
}

/*
parseKey tries to parse a PEM []byte slice using:
  - PKCS8
  - PKCS1
  - PKIX
  - EC

On success it returns the parsed key and nil.
On failure it returns nil and the error ErrFailedPEMParsing
*/
func parsePEMKey(data []byte) (any, error) {
	// Parse private keys
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS1PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParseECPrivateKey(data)
	if err == nil {
		return key, nil
	}

	// Parse public keys
	key, err = x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS1PublicKey(data)
	if err == nil {
		return key, nil
	}

	return nil, ErrFailedPEMParsing
}
