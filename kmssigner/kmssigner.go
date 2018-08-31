// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kmssigner implements a crypto.Signer backed by Google Cloud KMS.
package kmssigner

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/pkg/errors"

	cloudkms "github.com/google/google-api-go-client/cloudkms/v1"
)

// Signer extends crypto.Signer to provide more key metadata.
type Signer interface {
	crypto.Signer
	RSAPublicKey() *rsa.PublicKey
	CreationTime() time.Time
}

// New returns a crypto.Signer backed by the named Google Cloud KMS key.
func New(api *cloudkms.Service, name string) (Signer, error) {
	metadata, err := api.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.Get(name).Do()
	if err != nil {
		return nil, errors.WithMessage(err, "could not get key version from Google Cloud KMS API")
	}
	switch metadata.Algorithm {
	case "RSA_SIGN_PKCS1_2048_SHA256":
	case "RSA_SIGN_PKCS1_3072_SHA256":
	case "RSA_SIGN_PKCS1_4096_SHA256":
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", metadata.Algorithm)
	}

	creationTime, err := time.Parse(time.RFC3339Nano, metadata.CreateTime)
	if err != nil {
		return nil, errors.WithMessage(err, "could not parse key creation timestamp")
	}

	res, err := api.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(name).Do()
	if err != nil {
		return nil, errors.WithMessage(err, "could not get public key from Google Cloud KMS API")
	}
	block, _ := pem.Decode([]byte(res.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.WithMessage(err, "could not decode public key PEM")
	}
	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "could not parse public key")
	}
	pubkeyRSA, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.WithMessage(err, "public key was not an RSA key as expected")
	}
	return &kmsSigner{
		api:          api,
		name:         name,
		pubkey:       *pubkeyRSA,
		creationTime: creationTime,
	}, nil
}

type kmsSigner struct {
	api          *cloudkms.Service
	name         string
	pubkey       rsa.PublicKey
	creationTime time.Time
}

func (k *kmsSigner) Public() crypto.PublicKey {
	return k.pubkey
}

func (k *kmsSigner) RSAPublicKey() *rsa.PublicKey {
	return &k.pubkey
}

func (k *kmsSigner) CreationTime() time.Time {
	return k.creationTime
}

func (k *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("input digest must be valid SHA-256 hash")
	}
	sig, err := k.api.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(
		k.name,
		&cloudkms.AsymmetricSignRequest{
			Digest: &cloudkms.Digest{
				Sha256: base64.StdEncoding.EncodeToString(digest),
			},
		},
	).Do()
	if err != nil {
		return nil, errors.Wrap(err, "error signing with Google Cloud KMS")
	}
	res, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid Base64 response from Google Cloud KMS AsymmetricSign endpoint")
	}
	return res, nil
}
