// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	gkms "cloud.google.com/go/kms/apiv1"
	gsecretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	akms "github.com/aws/aws-sdk-go-v2/service/kms"
	asecretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gittuf/github-app/internal/awskms"
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

	var (
		signer ghinstallation.Signer
		err    error
	)
	if env.DevMode {
		// TODO: we should eventually remove this code path altogether

		log.Default().Println("App is deployed in dev mode, loading GitHub app signer from disk...")
		keyBytes, err := os.ReadFile(env.KMSKey)
		if err != nil {
			log.Panicf("unable to read signing key: %v", err)
		}

		_, rawKey, err := decodeAndParsePEM(keyBytes)
		if err != nil {
			log.Panicf("unable to parse signing key: %v", err)
		}

		key, ok := rawKey.(*rsa.PrivateKey)
		if !ok {
			log.Panicf("invalid key type, must be RSA")
		}

		signer = ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key)
		log.Printf("Created signer using on disk key")
	} else {
		switch env.CloudProvider {
		case cloudProviderAWS:
			log.Panic("AWS support isn't complete yet :(")

			kms := akms.New(akms.Options{})
			signer, err = awskms.New(ctx, kms, env.KMSKey)
			if err != nil {
				log.Panicf("error creating AWS signer: %v", err)
			}
		case cloudProviderGCP:
			kms, err := gkms.NewKeyManagementClient(ctx)
			if err != nil {
				log.Panicf("could not create kms client: %v", err)
			}
			signer, err = gcpkms.New(ctx, kms, env.KMSKey)
			if err != nil {
				log.Panicf("error creating GCP signer: %v", err)
			}
		}
	}

	transport, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, env.AppID, ghinstallation.WithSigner(signer))
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}
	if env.GitHubURL != webhook.DefaultGitHubURL {
		transport.BaseURL = fmt.Sprintf("%s/%s/%s/", env.GitHubURL, "api", "v3")
	}

	// Set up app signing key, assuming it's ssh and therefore a secret.
	// TODO: we should switch this to gitsign
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Panicf("unable to identify user's home directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0o755); err != nil {
		log.Panicf("unable to create .ssh directory: %v", err)
	}
	privateKeyPath := filepath.Join(homeDir, ".ssh", webhook.KeyFileName)

	webhookSecrets := [][]byte{}
	if env.DevMode {
		// TODO: we should eventually remove this code path altogether

		log.Default().Println("App is deployed in dev mode, loading webhook secrets from environment variable...")
		webhookSecrets = append(webhookSecrets, []byte(env.WebhookSecret))

		log.Default().Println("App is deployed in dev mode, loading metadata and commit signer from disk...")
		privkeyBytes, err := os.ReadFile(env.AppSigningKey)
		if err != nil {
			log.Panicf("error reading app signing key: %v", err)
		}
		if err := os.WriteFile(privateKeyPath, privkeyBytes, 0o600); err != nil {
			log.Panicf("error writing app signing key: %v", err)
		}

		pubkeyBytes, err := os.ReadFile(env.AppSigningPubKey)
		if err != nil {
			log.Panicf("error reading app public key: %v", err)
		}
		pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
		if err := os.WriteFile(pubkeyPath, pubkeyBytes, 0o600); err != nil {
			log.Panicf("error writing app public key: %v", err)
		}
	} else {
		switch env.CloudProvider {
		case cloudProviderAWS:
			log.Panic("AWS support isn't complete yet :(")

			secretmanager := asecretsmanager.New(asecretsmanager.Options{}) // TODO
			for _, name := range strings.Split(env.WebhookSecret, ",") {
				resp, err := secretmanager.GetSecretValue(ctx, &asecretsmanager.GetSecretValueInput{
					SecretId: &name,
				})
				if err != nil {
					log.Panicf("error fetching webhook secret '%s' from AWS: %v", name, err)
				}
				// TODO: may be SecretBinary?
				webhookSecrets = append(webhookSecrets, []byte(*resp.SecretString))
			}
		case cloudProviderGCP:
			secretmanager, err := gsecretmanager.NewClient(ctx)
			if err != nil {
				log.Panicf("could not create secret manager client: %v", err)
			}
			for _, name := range strings.Split(env.WebhookSecret, ",") {
				resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
					Name: name,
				})
				if err != nil {
					log.Panicf("error fetching webhook secret %s: %v", name, err)
				}
				webhookSecrets = append(webhookSecrets, resp.GetPayload().GetData())
			}

			resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
				Name: env.AppSigningKey,
			})
			if err != nil {
				log.Panicf("error fetching signing key: %v", err)
			}

			if err := os.WriteFile(privateKeyPath, resp.GetPayload().GetData(), 0o600); err != nil {
				log.Panicf("unable to write private key; %v", err)
			}

			resp, err = secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
				Name: env.AppSigningPubKey,
			})
			if err != nil {
				log.Panicf("error fetching public key: %v", err)
			}

			pubkeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
			if err := os.WriteFile(pubkeyPath, resp.GetPayload().GetData(), 0o600); err != nil {
				log.Panicf("unable to write public key; %v", err)
			}
		}
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
