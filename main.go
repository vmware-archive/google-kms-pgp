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

// Package main implements a PGP-compatible signing interface backed by Google KMS.
package main

import (
	"context"
	"fmt"
	"os"

	cloudkms "github.com/google/google-api-go-client/cloudkms/v1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/oauth2/google"

	"github.com/heptiolabs/google-kms-pgp/kmssigner"
)

var (
	cfg = packet.Config{}
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
usage: %s generate|sign

Commands:
	generate:
		Generate a PGP-compatible public key from the Google Cloud KMS key.

	sign:
		Sign the input from stdin and produce an ASCII-armored signature on stdout

Environment variables:
	KEY_NAME:
		Google Cloud KMS key version resource ID, for example:
		'projects/$PROJECT/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEYNAME/cryptoKeyVersions/1'
	GOOGLE_APPLICATION_CREDENTIALS (optional):
		Path to Google Cloud credentials file.
	PGP_UID_NAME (generate only):
		Name for generated PGP key (e.g., "Phil Zimmermann").
	PGP_UID_COMMENT (generate only, optional):
		Comment for generated PGP key.
	PGP_UID_EMAIL (generate only):
		Email for generated PGP key (e.g., "phil@example.com")
`, os.Args[0])
	os.Exit(1)
}

func run() error {
	keyName := os.Getenv("KEY_NAME")
	if keyName == "" || len(os.Args) != 2 {
		usage()
	}

	// Connect to the Google Cloud KMS API
	ctx := context.Background()
	oauthClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return errors.Wrap(err, "could not create Google Cloud OAuth client")
	}
	svc, err := cloudkms.New(oauthClient)
	if err != nil {
		return errors.Wrap(err, "could not create Google Cloud KMS client")
	}

	// Initialize a crypto.Signer backed by the configured Cloud KMS key.
	signer, err := kmssigner.New(svc, keyName)
	if err != nil {
		return errors.Wrap(err, "could not get KMS signer")
	}

	// Create an openpgp Entity, which holds the PGP-related information about our key.
	entity := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(signer.CreationTime(), signer.RSAPublicKey()),
		PrivateKey: packet.NewSignerPrivateKey(cfg.Now(), signer),
		Identities: make(map[string]*openpgp.Identity),
	}

	// TODO: this may be a bug in the openpgp library? Without this, my signatures
	// end up with a key ID that doesn't match the primary key.
	entity.PrivateKey.KeyId = entity.PrimaryKey.KeyId

	switch os.Args[1] {
	case "sign":
		// Emit
		if err := openpgp.ArmoredDetachSignText(os.Stdout, entity, os.Stdin, &cfg); err != nil {
			return errors.Wrap(err, "could not sign")
		}
	case "generate":
		uidName := os.Getenv("PGP_UID_NAME")
		uidComment := os.Getenv("PGP_UID_COMMENT")
		uidEmail := os.Getenv("PGP_UID_EMAIL")
		if uidName == "" || uidEmail == "" {
			usage()
		}
		uid := packet.NewUserId(uidName, uidComment, uidEmail)
		if uid == nil {
			return fmt.Errorf("could not generate PGP user ID metadata")
		}
		isPrimary := true
		entity.Identities[uid.Id] = &openpgp.Identity{
			Name:   uid.Id,
			UserId: uid,
			SelfSignature: &packet.Signature{
				CreationTime: cfg.Now(),
				SigType:      packet.SigTypePositiveCert,
				PubKeyAlgo:   packet.PubKeyAlgoRSA,
				Hash:         cfg.Hash(),
				IsPrimaryId:  &isPrimary,
				FlagsValid:   true,
				FlagSign:     true,
				FlagCertify:  true,
				IssuerKeyId:  &entity.PrimaryKey.KeyId,
			},
		}
		err := entity.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, entity.PrimaryKey, entity.PrivateKey, &cfg)
		if err != nil {
			return errors.WithMessage(err, "could not self-sign public key")
		}
		armoredWriter, err := armor.Encode(os.Stdout, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return errors.Wrap(err, "could not create ASCII-armored writer")
		}
		defer armoredWriter.Close()
		if err := entity.Serialize(armoredWriter); err != nil {
			return errors.Wrap(err, "could not serialize public key")
		}
	default:
		usage()
	}
	return nil
}
