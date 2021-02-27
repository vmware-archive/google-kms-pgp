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
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/s2k"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"

	"github.com/heptiolabs/google-kms-pgp/kmssigner"
)

var (
	cfg  = packet.Config{}
	opts = &options{}
)

type options struct {
	export            bool
	armor             bool
	detachedSignature bool
	sign              bool
	clearSign         bool
	localUser         string
	defaultKey        string
	key               string
	input             string
	output            string
	name              string
	comment           string
	email             string
}

func main() {
	// common options
	pflag.BoolVarP(&opts.armor, "armor", "a", opts.armor, "output in ascii armor")
	pflag.StringVarP(&opts.output, "output", "o", opts.output, "write output to file (use - for stdout)")

	// export options
	pflag.BoolVar(&opts.export, "export", opts.export, "export public key")
	pflag.StringVar(&opts.name, "name", opts.name, "name associated with the key")
	pflag.StringVar(&opts.comment, "comment", opts.comment, "comment associated with the key")
	pflag.StringVar(&opts.email, "email", opts.email, "email associated with the key")

	// sign options
	pflag.BoolVarP(&opts.sign, "sign", "s", opts.sign, "sign a message")
	pflag.BoolVar(&opts.clearSign, "clearsign", opts.sign, "sign a message in clear text")
	pflag.StringVarP(&opts.localUser, "local-user", "u", opts.localUser, "name of key to sign with")
	pflag.StringVar(&opts.defaultKey, "default-key", opts.defaultKey, "name of key to sign with")
	pflag.BoolVarP(&opts.detachedSignature, "detach-sign", "b", opts.detachedSignature, "make a detached signature")

	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()

	// local-user and default-key are mutually exclusive, for our purposes
	if opts.localUser != "" && opts.defaultKey != "" {
		fmt.Fprintln(os.Stderr, "you may set either local-user or default-key, but not both")
		os.Exit(1)
	}

	if opts.localUser != "" {
		opts.key = opts.localUser
	}

	if opts.defaultKey != "" {
		opts.key = opts.defaultKey
	}

	var err error

	switch {
	case opts.export:
		args := pflag.Args()
		if len(args) != 1 {
			usage("--export --name NAME [--comment COMMENT] --email EMAIL [--armor] [--output OUTPUT] KEY")
		}

		opts.key = args[0]
		err = runExport(opts)
	case opts.sign, opts.clearSign, opts.detachedSignature:
		if opts.key == "" {
			usage("--sign|--clearsign --local-user KEY [--detach-sign] [--armor] [--output OUTPUT] [INPUT]")
		}

		args := pflag.Args()
		if len(args) == 1 {
			opts.input = args[0]
		}

		err = runSign(opts)
	default:
		usage("--export|--sign|--clearsign")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage(msg string) {
	fmt.Fprintf(os.Stderr, "usage: %s %s\n", os.Args[0], msg)
	pflag.CommandLine.PrintDefaults()
	os.Exit(1)
}

func runExport(opts *options) error {
	if opts.key == "" {
		return errors.New("key is required")
	}

	if opts.name == "" {
		return errors.New("name is required")
	}

	if opts.email == "" {
		return errors.New("email is required")
	}

	entity, err := getEntity(opts.key)
	if err != nil {
		return err
	}

	uid := packet.NewUserId(opts.name, opts.comment, opts.email)
	if uid == nil {
		return errors.Errorf("could not generate PGP user ID metadata")
	}

	isPrimary := true
	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: entity.PrimaryKey.CreationTime,
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

	if err := entity.Identities[uid.Id].SelfSignature.SignUserId(
		uid.Id,
		entity.PrimaryKey,
		entity.PrivateKey,
		&cfg,
	); err != nil {
		return errors.WithMessage(err, "could not self-sign public key")
	}

	var out io.Writer

	switch opts.output {
	case "", "-":
		out = os.Stdout
	default:
		outFile, err := os.Create(opts.output)
		if err != nil {
			return errors.Wrapf(err, "unable to create output file %q", opts.output)
		}

		defer outFile.Close()
		out = outFile
	}

	if opts.armor {
		armoredWriter, err := armor.Encode(out, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return errors.Wrap(err, "could not create ASCII-armored writer")
		}

		if err := entity.Serialize(armoredWriter); err != nil {
			return errors.Wrap(err, "could not serialize public key")
		}

		if err := armoredWriter.Close(); err != nil {
			return errors.Wrap(err, "error closing ASCII-armored writer")
		}

		// Always add a blank line to the end of the raw output
		fmt.Fprintf(out, "\n")
	} else if err := entity.Serialize(out); err != nil {
		return errors.Wrap(err, "could not serialize public key")
	}

	return nil
}

func runSign(opts *options) error {
	if opts.key == "" {
		return errors.New("key is required")
	}

	entity, err := getEntity(opts.key)
	if err != nil {
		return err
	}

	if opts.output == "" {
		if opts.detachedSignature || opts.clearSign {
			opts.output = opts.input + ".asc"
		} else {
			opts.output = opts.input + ".gpg"
		}
	}

	var output io.Writer = os.Stdout
	var input io.Reader = os.Stdin

	if opts.output != "-" {
		outputFile, err := os.Create(opts.output)
		if err != nil {
			return err
		}

		defer outputFile.Close()
		output = outputFile
	}

	if opts.input != "" {
		inputFile, err := os.Open(opts.input)
		if err != nil {
			return err
		}

		defer inputFile.Close()
		input = inputFile
	}

	switch {
	case opts.detachedSignature && opts.armor:
		if err := openpgp.ArmoredDetachSign(output, entity, input, &cfg); err != nil {
			return err
		}

		fmt.Fprintf(output, "\n")
		return nil
	case opts.detachedSignature && !opts.armor:
		return openpgp.DetachSign(output, entity, input, &cfg)
	case !opts.detachedSignature:
		// Set up an "identity" so we can control the hash algorithm
		hashIDSha256, ok := s2k.HashToHashId(crypto.SHA256)
		if !ok {
			return errors.New("unable to get pgp hash id for sha256")
		}

		entity.Identities["HACK"] = &openpgp.Identity{
			SelfSignature: &packet.Signature{
				PreferredHash: []uint8{
					hashIDSha256,
				},
			},
		}

		// If we're doing a real file, set up hints for it
		fileHints := &openpgp.FileHints{}
		if opts.input != "" {
			fileHints.FileName = opts.input
			fileInfo, err := os.Stat(opts.input)
			if err != nil {
				return err
			}

			fileHints.ModTime = fileInfo.ModTime()
		}

		// Get ready to sign
		var (
			writeCloser io.WriteCloser
			addNewline  bool
		)

		if opts.clearSign {
			addNewline = true
			writeCloser, err = clearsign.Encode(output, entity.PrivateKey, &cfg)
		} else {
			writeCloser, err = openpgp.Sign(output, entity, fileHints, &cfg)
		}

		if err != nil {
			return err
		}

		// Copy the data from input to writeCloser so it will perform signing
		_, copyErr := io.Copy(writeCloser, input)

		// Always try to close
		closeErr := writeCloser.Close()

		if copyErr != nil {
			return copyErr
		}

		if closeErr != nil {
			return closeErr
		}

		if addNewline {
			fmt.Fprintf(output, "\n")
		}

		return nil
	}

	return nil
}

func getEntity(key string) (*openpgp.Entity, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}

	// Connect to the Google Cloud KMS API
	ctx := context.Background()
	oauthClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, errors.Wrap(err, "could not create Google Cloud OAuth client")
	}

	svc, err := cloudkms.New(oauthClient)
	if err != nil {
		return nil, errors.Wrap(err, "could not create Google Cloud KMS client")
	}

	// Initialize a crypto.Signer backed by the configured Cloud KMS key.
	signer, err := kmssigner.New(svc, key)
	if err != nil {
		return nil, errors.Wrap(err, "could not get KMS signer")
	}

	// Create an openpgp Entity, which holds the PGP-related information about our key.
	entity := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(signer.CreationTime(), signer.RSAPublicKey()),
		PrivateKey: packet.NewSignerPrivateKey(cfg.Now(), signer),
		Identities: make(map[string]*openpgp.Identity),
	}

	// The PubKeyAlgo defaults to packet.PubKeyAlgoRSASignOnly, and that doesn't work for RPM
	entity.PrivateKey.PubKeyAlgo = packet.PubKeyAlgoRSA

	// TODO: this may be a bug in the openpgp library? Without this, my signatures
	// end up with a key ID that doesn't match the primary key.
	entity.PrivateKey.KeyId = entity.PrimaryKey.KeyId

	return entity, nil
}
