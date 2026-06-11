// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	gkms "cloud.google.com/go/kms/apiv1"
	gsecretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/octo-sts/app/pkg/gcpkms"
	"golang.org/x/crypto/ssh"
)

const (
	cloudProviderAWS = "aws"
	cloudProviderGCP = "gcp"
)

var ErrNotImplemented = errors.New("this functionality is not implemented yet")

type provider interface {
	GetWebhookSecrets(context.Context) ([][]byte, error)
	PrepareGitSigningKey(context.Context) error
	GetTransportSigner(context.Context) (ghinstallation.Signer, error)
}

type devModeSSHProvider struct {
	env *EnvConfig
}

func (p *devModeSSHProvider) GetWebhookSecrets(_ context.Context) ([][]byte, error) {
	return [][]byte{[]byte(p.env.WebhookSecret)}, nil
}

func (p *devModeSSHProvider) PrepareGitSigningKey(_ context.Context) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("unable to identify user's home directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0o755); err != nil {
		return fmt.Errorf("unable to create .ssh directory: %w", err)
	}
	privateKeyPath := filepath.Join(homeDir, ".ssh", KeyFileName)

	privkeyBytes, err := os.ReadFile(p.env.AppSigningKey) //nolint:gosec
	if err != nil {
		return fmt.Errorf("error reading app signing key: %w", err)
	}
	if err := os.WriteFile(privateKeyPath, privkeyBytes, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("error writing app signing key: %w", err)
	}

	pubkeyBytes, err := os.ReadFile(p.env.AppSigningPubKey) //nolint:gosec
	if err != nil {
		return fmt.Errorf("error reading app public key: %w", err)
	}
	pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if err := os.WriteFile(pubkeyPath, pubkeyBytes, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("error writing app public key: %w", err)
	}

	return nil
}

func (p *devModeSSHProvider) GetTransportSigner(_ context.Context) (ghinstallation.Signer, error) {
	keyBytes, err := os.ReadFile(p.env.KMSKey) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("unable to read signing key: %w", err)
	}

	_, rawKey, err := decodeAndParsePEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signing key: %w", err)
	}

	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, must be RSA")
	}

	return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
}

type devModeGPGProvider struct {
	env *EnvConfig
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
		return fmt.Errorf("error importing GPG key: %w, output: %s", err, string(output))
	}

	return nil
}

func (p *devModeGPGProvider) GetTransportSigner(_ context.Context) (ghinstallation.Signer, error) {
	keyBytes, err := os.ReadFile(p.env.KMSKey) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("unable to read signing key: %w", err)
	}

	_, rawKey, err := decodeAndParsePEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signing key: %w", err)
	}

	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, must be RSA")
	}

	return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
}

type gcpProvider struct {
	env           *EnvConfig
	secretManager *gsecretmanager.Client
}

func (p *gcpProvider) getSecretManagerClient(ctx context.Context) (*gsecretmanager.Client, error) {
	if p.secretManager != nil {
		return p.secretManager, nil
	}

	secretManager, err := gsecretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create secret manager client: %w", err)
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
			return nil, fmt.Errorf("error fetching webhook secret %s: %w", name, err)
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
		return fmt.Errorf("error fetching signing key: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("unable to identify user's home directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0o755); err != nil {
		return fmt.Errorf("unable to create .ssh directory: %w", err)
	}
	privateKeyPath := filepath.Join(homeDir, ".ssh", KeyFileName)

	if err := os.WriteFile(privateKeyPath, resp.GetPayload().GetData(), 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("unable to write private key; %w", err)
	}

	resp, err = secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: p.env.AppSigningPubKey,
	})
	if err != nil {
		return fmt.Errorf("error fetching public key: %w", err)
	}

	pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if err := os.WriteFile(pubkeyPath, resp.GetPayload().GetData(), 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("unable to write public key; %w", err)
	}

	return nil
}

func (p *gcpProvider) GetTransportSigner(ctx context.Context) (ghinstallation.Signer, error) {
	kms, err := gkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create kms client: %w", err)
	}
	return gcpkms.New(ctx, kms, p.env.KMSKey)
}

type awsProvider struct {
	env *EnvConfig
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
func decodeAndParsePEM(pemBytes []byte) (*pem.Block, any, error) { //nolint:unparam
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
