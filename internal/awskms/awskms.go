// SPDX-License-Identifier: Apache-2.0

package awskms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

type signingMethodAWS struct {
	client *kms.Client
}

func (s *signingMethodAWS) Verify(string, string, any) error {
	return errors.New("not implemented")
}

func (s *signingMethodAWS) Sign(signingString string, ikey any) (string, error) {
	ctx := context.Background()

	key, ok := ikey.(string)
	if !ok {
		return "", fmt.Errorf("invalid key reference type: %T", ikey)
	}

	key = strings.TrimPrefix(key, "aws:")

	input := &kms.SignInput{
		KeyId:   &key,
		Message: []byte(signingString),
		// TODO: other fields?
	}

	resp, err := s.client.Sign(ctx, input)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(resp.Signature), nil
}

func (s *signingMethodAWS) Alg() string {
	return "RS256"
}

type awsSigner struct {
	client *kms.Client
	key    string
}

func New(_ context.Context, client *kms.Client, key string) (ghinstallation.Signer, error) {
	return &awsSigner{
		client: client,
		key:    key,
	}, nil
}

// Sign signs the JWT claims with the RSA key.
func (s *awsSigner) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethodAWS{
		client: s.client,
	}
	return jwt.NewWithClaims(method, claims).SignedString(s.key)
}
