# Build + deploy targets for the Rift signing enclave + parent proxy.
#
# All targets except `check`/`test` assume you're running on the
# c6g.large EC2 with Docker and nitro-cli installed (see step 1.x of
# the README + DEPLOYMENT.md).

IMAGE := rift-signer-enclave
TAG ?= latest
EIF := rift-signer.eif

# Allocator config we set up in step 2.2: 1 vCPU + 1024 MiB to the
# enclave on c6g.large.
ENCLAVE_CPUS ?= 1
ENCLAVE_MEMORY_MIB ?= 1024

.PHONY: help
help:
	@echo "Common targets:"
	@echo "  make check                   # cargo check (no build, fast)"
	@echo "  make test                    # unit tests for portable modules"
	@echo "  make build-enclave           # cargo build --release --bin rift-signer-enclave"
	@echo "  make build-parent-proxy      # cargo build --release --bin rift-parent-proxy"
	@echo "  make build                   # both above"
	@echo "  make image                   # Docker image for the enclave"
	@echo "  make eif                     # build the EIF (depends on image)"
	@echo "  make pcr0                    # print the EIF's PCR0 (use in KMS key policy)"
	@echo "  make run-debug               # launch enclave in debug-mode"
	@echo "  make run                     # launch enclave in production mode"
	@echo "  make describe                # show running enclaves"
	@echo "  make console                 # tail enclave console output"
	@echo "  make kill                    # terminate all running enclaves"
	@echo "  make install-parent-proxy    # install parent proxy as systemd unit"
	@echo "  make clean                   # rm EIF + cargo target dir"

.PHONY: check
check:
	cargo check --locked --workspace

.PHONY: test
test:
	cargo test --locked --workspace

.PHONY: build-enclave
build-enclave:
	cargo build --release --bin rift-signer-enclave

.PHONY: build-parent-proxy
build-parent-proxy:
	cargo build --release --bin rift-parent-proxy

.PHONY: build
build: build-enclave build-parent-proxy

.PHONY: image
image:
	docker build -t $(IMAGE):$(TAG) -f Dockerfile .

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

# ─── Parent-proxy systemd install ──────────────────────────────────
# Builds the parent proxy and installs it as a systemd unit so it
# survives reboots and restarts the smart-wallet sees timeouts cleanly.
.PHONY: install-parent-proxy
install-parent-proxy: build-parent-proxy
	sudo cp target/release/rift-parent-proxy /usr/local/bin/rift-parent-proxy
	sudo cp systemd/rift-parent-proxy.service /etc/systemd/system/rift-parent-proxy.service
	sudo systemctl daemon-reload
	sudo systemctl enable --now rift-parent-proxy.service
	@echo "✓ parent-proxy installed and running"
	@echo "  systemctl status rift-parent-proxy"
	@echo "  journalctl -u rift-parent-proxy -f"

.PHONY: clean
clean:
	rm -f $(EIF)
	cargo clean
