#!/usr/bin/env bash

# TODO(LICENSE): Needs copyright header

set -o errexit
set -o nounset
set -o pipefail

go mod tidy
git diff --exit-code go.*
