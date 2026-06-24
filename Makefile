# Build + deploy targets for the Rift signing enclave.
#
# All targets assume you're running on the c6g.large EC2 with Docker
# and nitro-cli installed (see step 1.x of the README). Local Mac /
# Windows dev: use `make check` for a fast cargo type-check; for
# anything else, ssh to the EC2 (via SSM Session Manager) and run
# there.

IMAGE := rift-signer-enclave
TAG ?= latest
EIF := rift-signer.eif

# How many vCPUs + MiB to give the enclave at run time. c6g.large has
# 2 vCPU + 4 GiB total; we keep 1 vCPU + 512 MiB for the parent OS.
# These match the allocator config we set up in step 2.2.
ENCLAVE_CPUS ?= 1
ENCLAVE_MEMORY_MIB ?= 1024

.PHONY: help
help:
	@echo "Common targets:"
	@echo "  make check        # cargo check (no full build, fast)"
	@echo "  make build        # cargo build --release"
	@echo "  make image        # build the Docker image"
	@echo "  make eif          # build the enclave image file (EIF)"
	@echo "  make run-debug    # launch the enclave in debug-mode + tail console"
	@echo "  make run          # launch the enclave in production mode (no console)"
	@echo "  make describe     # show running enclaves"
	@echo "  make kill         # terminate all running enclaves"
	@echo "  make pcr0         # print the PCR0 of the current EIF (use in KMS key policy)"
	@echo "  make clean        # remove EIF + cargo target dir"

.PHONY: check
check:
	cargo check --locked

.PHONY: build
build:
	cargo build --release --locked

.PHONY: image
image:
	docker build -t $(IMAGE):$(TAG) .

.PHONY: eif
eif: image
	sudo nitro-cli build-enclave \
	  --docker-uri $(IMAGE):$(TAG) \
	  --output-file $(EIF)

.PHONY: pcr0
pcr0:
	@sudo nitro-cli describe-eif --eif-path $(EIF) \
	  | grep -A1 '"PCR0"' \
	  | tail -1 \
	  | tr -d ' ",'

.PHONY: run-debug
run-debug: eif
	sudo nitro-cli run-enclave \
	  --eif-path $(EIF) \
	  --memory $(ENCLAVE_MEMORY_MIB) \
	  --cpu-count $(ENCLAVE_CPUS) \
	  --debug-mode
	@echo
	@echo "Enclave running. Tail console with: make console"

.PHONY: run
run: eif
	sudo nitro-cli run-enclave \
	  --eif-path $(EIF) \
	  --memory $(ENCLAVE_MEMORY_MIB) \
	  --cpu-count $(ENCLAVE_CPUS)

.PHONY: console
console:
	@ENCLAVE_ID=$$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID'); \
	if [ -z "$$ENCLAVE_ID" ] || [ "$$ENCLAVE_ID" = "null" ]; then \
	  echo "no running enclave"; exit 1; \
	fi; \
	sudo nitro-cli console --enclave-id "$$ENCLAVE_ID"

.PHONY: describe
describe:
	sudo nitro-cli describe-enclaves

.PHONY: kill
kill:
	@for id in $$(sudo nitro-cli describe-enclaves | jq -r '.[].EnclaveID'); do \
	  echo "terminating $$id"; \
	  sudo nitro-cli terminate-enclave --enclave-id "$$id"; \
	done

.PHONY: clean
clean:
	rm -f $(EIF)
	cargo clean
