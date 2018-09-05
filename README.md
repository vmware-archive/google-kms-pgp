# Google KMS PGP

This project lets you create PGP-compatible signatures using [Google Cloud KMS] asymmetric keys.
It should be considered experimental.

## Installing

```console
$ go get -u -v github.com/heptiolabs/google-kms-pgp
[...]
$ google-kms-pgp

usage: google-kms-pgp --export|--sign|--clearsign
  -a, --armor               output in ascii armor
      --clearsign           sign a message in clear text
      --comment string      comment associated with the key
  -b, --detach-sign         make a detached signature
      --email string        email associated with the key
      --export              export public key
  -u, --local-user string   name of key to sign with
      --name string         name associated with the key
  -o, --output string       write output to file (use - for stdout)
  -s, --sign                sign a message
```

This binary has two modes of execution:

- `--export`: generates and exports a PGP-compatible public key from a Google Cloud KMS key.

- `--sign|--clearsign`: signs input using the Google Cloud KMS key, producing a PGP signature.

## Usage: Generating a Key

```console
$ export GOOGLE_APPLICATION_CREDENTIALS=./path/to/google/credentials.json

$ google-kms-pgp --export \
								 --name "My User" \
								 --comment "A comment about my key" \
								 --email "myuser@example.com" \
								 --armor \
								 --output my-public-key.asc \
								 projects/my-project/locations/my-location/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1

$ gpg --import my-public-key.asc
gpg: key 6014DEDCDEC1EF5F: "My User (A comment about my key) <myuser@example.com>" 1 new user ID
gpg: key 6014DEDCDEC1EF5F: "My User (A comment about my key) <myuser@example.com>" 1 new signature
gpg: Total number processed: 1
gpg:           new user IDs: 1
gpg:         new signatures: 1
```

You can import this key into GPG using `gpg --import my-public-key.asc` and optionally mark it trusted using `gpg --edit-key 6014DEDCDEC1EF5F`

## Usage: Signing

```console
$ export GOOGLE_APPLICATION_CREDENTIALS=./path/to/google/credentials.json

$ google-kms-pgp --sign \
								 --detach-sign \
								 --armor \
								 --local-user projects/my-project/locations/my-location/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1 \
								 hello.txt

$ gpg --verify hello.txt.asc hello.txt
gpg: Signature made Fri Aug 31 11:48:35 2018 CDT
gpg:                using RSA key 6014DEDCDEC1EF5F
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   2  signed:   5  trust: 0-, 0q, 0n, 0m, 0f, 2u
gpg: depth: 1  valid:   5  signed:   5  trust: 5-, 0q, 0n, 0m, 0f, 0u
gpg: Good signature from "My User (A comment about my key) <myuser@example.com>" [ultimate]
```

[Google Cloud KMS]: https://cloud.google.com/kms/
