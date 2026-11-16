# Every target runs outside any parent go.work so results match CI.
export GOWORK := off
SHELL := /usr/bin/env bash -o pipefail -e

BIN := $(CURDIR)/bin
CONTROLLER_GEN_VERSION := v0.23.0
SETUP_ENVTEST_VERSION := release-0.25
GOVULNCHECK_VERSION := v1.9.0
ENVTEST_K8S_VERSION := 1.37.0
HELM_VERSION := v4.3.2
KUBECONFORM_VERSION := v0.8.0
KIND_VERSION := v0.33.0
KO_VERSION := v0.19.1
HELM_DOCS_VERSION := v1.14.2
CFN_LINT_VERSION := 1.60.1
CRANE_VERSION := v0.22.1
# The CNIs the data-path end-to-end test runs under, besides kindnet.
CILIUM_VERSION := 1.20.4
CALICO_VERSION := v3.33.0
# The service meshes it runs under, and the Gateway API CRDs Linkerd needs.
ISTIO_VERSION := 1.30.8
LINKERD_VERSION := 2026.11.2
GATEWAY_API_VERSION := v1.7.0
# clang and libbpf for the eBPF fast path, pinned so every build of the
# object is byte for byte the same.
BPF_BUILDER := ghcr.io/cilium/ebpf-builder:1793281567@sha256:1090b14b4ff21fa58a8d7c4eb449a3a9ad34fd8408e08a14a20a4656817d690b
BPF_DIR := internal/agent/dataplane/bpf

CONTROLLER_GEN := $(BIN)/controller-gen-$(CONTROLLER_GEN_VERSION)
SETUP_ENVTEST := $(BIN)/setup-envtest-$(SETUP_ENVTEST_VERSION)
GOVULNCHECK := $(BIN)/govulncheck-$(GOVULNCHECK_VERSION)
HELM := $(BIN)/helm-$(HELM_VERSION)
KUBECONFORM := $(BIN)/kubeconform-$(KUBECONFORM_VERSION)
KIND := $(BIN)/kind-$(KIND_VERSION)
KO := $(BIN)/ko-$(KO_VERSION)
HELM_DOCS := $(BIN)/helm-docs-$(HELM_DOCS_VERSION)
CRANE := $(BIN)/crane-$(CRANE_VERSION)
# Chart scripts find the pinned tools first.
CHART_PATH := $(BIN)/chart-tools:$(PATH)

.PHONY: check
check: verify-generated lint test vuln ## Everything CI runs on Go code

.PHONY: generate
generate: $(CONTROLLER_GEN) bpf ## Regenerate deepcopy code, CRDs and the eBPF object
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...
	rm -f config/crd/*.yaml
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd
	rm -f charts/natterjack/files/crds/*.yaml
	cp config/crd/*.yaml charts/natterjack/files/crds/

.PHONY: bpf
bpf: ## Build the eBPF objects: the fast path and the probe responder (needs Docker)
	docker run --rm --platform linux/amd64 --network none -u "$$(id -u):$$(id -g)" \
		-v "$(CURDIR)/$(BPF_DIR):/src" -w /src $(BPF_BUILDER) sh -ec '\
		for p in steer respond; do \
			clang-22 -O2 -g -Wall -Werror -target bpfel -mcpu=v3 -I/usr/include/x86_64-linux-gnu -c $$p.c -o $${p}_bpfel.o; \
			llvm-strip-22 -g $${p}_bpfel.o; \
		done'

GENERATED := api config charts/natterjack/files $(BPF_DIR)

.PHONY: verify-generated
verify-generated: generate ## Fail if generated files are out of date
	@git diff --exit-code -- $(GENERATED) || { echo "generated files are stale: run 'make generate' and commit"; exit 1; }
	@test -z "$$(git status --porcelain -- $(GENERATED))" || { git status --porcelain -- $(GENERATED); echo "untracked generated files: run 'make generate' and commit"; exit 1; }

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

.PHONY: chart-lint
chart-lint: chart-tools ## Lint the chart, validate every rendering, check bad input is refused
	PATH="$(CHART_PATH)" ./hack/chart-lint.sh

.PHONY: chart-docs
chart-docs: chart-tools ## Regenerate the chart README's and the site's values reference
	$(HELM_DOCS) --chart-search-root charts --template-files README.md.gotmpl
	$(HELM_DOCS) --chart-search-root charts --template-files $(CURDIR)/site/helm-values.md.gotmpl \
		--output-file ../../site/content/docs/reference/helm-values/_index.md

.PHONY: chart-e2e
chart-e2e: chart-tools ## Install the chart on a throwaway kind cluster and prove it (needs Docker)
	PATH="$(CHART_PATH)" ./hack/chart-e2e.sh $(KIND_NODE_IMAGE)

CNI ?= kindnet
MESH ?=

.PHONY: datapath-e2e
datapath-e2e: chart-tools ## Send real egress traffic through a kind cluster and a fake EC2 under CNI=kindnet|cilium|calico, optionally MESH=istio|ambient|linkerd (needs Docker)
	PATH="$(CHART_PATH)" CILIUM_VERSION=$(CILIUM_VERSION) CALICO_VERSION=$(CALICO_VERSION) \
		ISTIO_VERSION=$(ISTIO_VERSION) LINKERD_VERSION=$(LINKERD_VERSION) GATEWAY_API_VERSION=$(GATEWAY_API_VERSION) \
		MESH=$(MESH) ./hack/datapath-e2e.sh $(CNI) $(KIND_NODE_IMAGE)

.PHONY: eks-e2e
eks-e2e: chart-tools ## Run the end-to-end suite on the EKS cluster test/eks built (needs AWS credentials, OUT, TF_VAR_run_id, TF_VAR_api_allowed_cidrs)
	PATH="$(CHART_PATH)" ./hack/eks-e2e.sh

.PHONY: chart-tools
chart-tools: $(HELM) $(KUBECONFORM) $(KIND) $(KO) $(HELM_DOCS) $(CRANE)
	mkdir -p $(BIN)/chart-tools
	ln -sf $(HELM) $(BIN)/chart-tools/helm
	ln -sf $(KUBECONFORM) $(BIN)/chart-tools/kubeconform
	ln -sf $(KIND) $(BIN)/chart-tools/kind
	ln -sf $(KO) $(BIN)/chart-tools/ko
	ln -sf $(HELM_DOCS) $(BIN)/chart-tools/helm-docs
	ln -sf $(CRANE) $(BIN)/chart-tools/crane

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

.PHONY: cfn-check
cfn-check: ## Lint the CloudFormation templates
	pipx run --spec cfn-lint==$(CFN_LINT_VERSION) cfn-lint deploy/cloudformation/*.yaml

$(TERRAFORM_DOCS):
	GOBIN=$(BIN) go install github.com/terraform-docs/terraform-docs@$(TERRAFORM_DOCS_VERSION)
	mv $(BIN)/terraform-docs $@

$(HELM):
	GOBIN=$(BIN) go install helm.sh/helm/v4/cmd/helm@$(HELM_VERSION)
	mv $(BIN)/helm $@

$(HELM_DOCS):
	GOBIN=$(BIN) go install github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)
	mv $(BIN)/helm-docs $@

$(KUBECONFORM):
	GOBIN=$(BIN) go install github.com/yannh/kubeconform/cmd/kubeconform@$(KUBECONFORM_VERSION)
	mv $(BIN)/kubeconform $@

$(KIND):
	GOBIN=$(BIN) go install sigs.k8s.io/kind@$(KIND_VERSION)
	mv $(BIN)/kind $@

$(KO):
	GOBIN=$(BIN) go install github.com/google/ko@$(KO_VERSION)
	mv $(BIN)/ko $@

.PHONY: release-dry-run
release-dry-run: chart-tools ## Build and push a release to a throwaway local registry and check it
	PATH="$(CHART_PATH)" ./hack/release-dry-run.sh

$(CRANE):
	GOBIN=$(BIN) go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	mv $(BIN)/crane $@

.PHONY: help
help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "%-18s %s\n", $$1, $$2}'
