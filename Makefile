# Every target runs outside any parent go.work so results match CI.
export GOWORK := off
SHELL := /usr/bin/env bash -o pipefail -e

BIN := $(CURDIR)/bin
CONTROLLER_GEN_VERSION := v0.23.0
SETUP_ENVTEST_VERSION := release-0.25
GOVULNCHECK_VERSION := v1.9.0
ENVTEST_K8S_VERSION := 1.37.0

CONTROLLER_GEN := $(BIN)/controller-gen-$(CONTROLLER_GEN_VERSION)
SETUP_ENVTEST := $(BIN)/setup-envtest-$(SETUP_ENVTEST_VERSION)
GOVULNCHECK := $(BIN)/govulncheck-$(GOVULNCHECK_VERSION)

.PHONY: check
check: verify-generated lint test vuln ## Everything CI runs on Go code

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Regenerate deepcopy code and CRDs
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...
	rm -f config/crd/*.yaml
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd

.PHONY: verify-generated
verify-generated: generate ## Fail if generated files are out of date
	@git diff --exit-code -- api config || { echo "generated files are stale: run 'make generate' and commit"; exit 1; }
	@test -z "$$(git status --porcelain -- api config)" || { git status --porcelain -- api config; echo "untracked generated files: run 'make generate' and commit"; exit 1; }

.PHONY: lint
lint: ## golangci-lint (install from https://golangci-lint.run)
	golangci-lint run ./...

.PHONY: test
test: $(SETUP_ENVTEST) ## Unit and envtest suites with the race detector
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S_VERSION) --bin-dir $(BIN)/k8s)" \
		go test -race -count=1 -coverprofile=cover.out ./...

.PHONY: test-privileged
test-privileged: ## Data path tests in throwaway privileged containers (needs Docker)
	./hack/test-privileged.sh

.PHONY: vuln
vuln: $(GOVULNCHECK) ## Known vulnerabilities reachable from our code
	$(GOVULNCHECK) ./...

$(CONTROLLER_GEN):
	GOBIN=$(BIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
	mv $(BIN)/controller-gen $@

$(SETUP_ENVTEST):
	GOBIN=$(BIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
	mv $(BIN)/setup-envtest $@

$(GOVULNCHECK):
	GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	mv $(BIN)/govulncheck $@

# Terraform modules: formatted, valid, tested against a mocked provider, and
# their README reference current.
TERRAFORM_DOCS_VERSION := v0.25.1
TERRAFORM_DOCS := $(BIN)/terraform-docs-$(TERRAFORM_DOCS_VERSION)
TF_MODULES := $(wildcard deploy/terraform/*)

.PHONY: terraform-check
terraform-check: $(TERRAFORM_DOCS) ## Format, validate, test and document the Terraform modules
	terraform fmt -check -recursive deploy/terraform
	set -e; for m in $(TF_MODULES); do \
		terraform -chdir=$$m init -backend=false -input=false >/dev/null; \
		terraform -chdir=$$m validate; \
		terraform -chdir=$$m test; \
		$(TERRAFORM_DOCS) $$m >/dev/null; \
	done
	git diff --exit-code -- $(addsuffix /README.md,$(TF_MODULES)) || { echo "A module README is stale: run 'make terraform-check' and commit"; exit 1; }

$(TERRAFORM_DOCS):
	GOBIN=$(BIN) go install github.com/terraform-docs/terraform-docs@$(TERRAFORM_DOCS_VERSION)
	mv $(BIN)/terraform-docs $@

.PHONY: help
help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "%-18s %s\n", $$1, $$2}'
