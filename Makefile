# TODO(LICENSE): Needs copyright header

# If you update this file, please follow
# https://suva.sh/posts/well-documented-makefiles

REPO_ROOT	:= $(shell git rev-parse --show-toplevel)

.DEFAULT_GOAL:=help
SHELL:=/usr/bin/env bash

COLOR:=\\033[36m
NOCOLOR:=\\033[0m

##@ Verify

.PHONY: verify-golangci-lint verify-go-mod

verify: verify-golangci-lint verify-go-mod ## Runs verification scripts to ensure correct execution

verify-go-mod: ## Runs the go module linter
	${REPO_ROOT}/scripts/verify-go-mod.sh

verify-golangci-lint: ## Runs all golang linters
	${REPO_ROOT}/scripts/verify-golangci-lint.sh

##@ Helpers

.PHONY: help

help:  ## Display this help
	@awk \
		-v "col=${COLOR}" -v "nocol=${NOCOLOR}" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "\nUsage:\n  make %s<target>%s\n", col, nocol \
			} \
			/^[a-zA-Z_-]+:.*?##/ { \
				printf "  %s%-15s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)
