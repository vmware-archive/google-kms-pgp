# Google KMS PGP

This project lets you create PGP-compatible signatures using [Google Cloud KMS] asymmetric keys.
It should be considered experimental.

## Installing

```console
$ go get -u -v github.com/heptiolabs/google-kms-pgp
[...]
$ google-kms-pgp

usage: google-kms-pgp generate|sign

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
```

This binary has two subcommands:

- `generate`: generates a PGP-compatible public key from a Google Cloud KMS key.

- `sign`: signs input using the Google Cloud KMS key, producing an ASCII-armored PGP detached signature.

## Usage: Generating a Key

```console
$ export GOOGLE_APPLICATION_CREDENTIALS=./path/to/google/credentials.json
$ export KEY_NAME=projects/my-project/locations/my-location/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1
$ export PGP_UID_NAME="My User"
$ export PGP_UID_COMMENT="A comment about my key"
$ export PGP_UID_EMAIL="myuser@example.com"
$ google-kms-pgp generate > my-public-key.asc
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
$ export KEY_NAME=projects/my-project/locations/my-location/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1
$ google-kms-pgp sign < hello.txt > hello.txt.asc
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