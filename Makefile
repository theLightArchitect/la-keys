# L-ARC API Key Service — Makefile
# Standard targets matching Light Architects ecosystem

BINARY_NAME := larc-keys
DEPLOY_DIR := $(HOME)/.larc
DEPLOY_BIN := $(DEPLOY_DIR)/bin/$(BINARY_NAME)

.PHONY: help build test quality fix deploy deploy-fast push clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build release binary
	cargo build --release --bin $(BINARY_NAME)

test: ## Run all tests
	cargo test --all-features

quality: ## Run quality gates (fmt check + clippy + tests)
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all-features

fix: ## Auto-fix fmt + clippy issues
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

deploy: quality build ## Quality gates + build + deploy
	@mkdir -p $(DEPLOY_DIR)/bin
	@if [ -f "$(DEPLOY_BIN)" ]; then cp "$(DEPLOY_BIN)" "$(DEPLOY_BIN).bak"; fi
	cp target/release/$(BINARY_NAME) $(DEPLOY_BIN)
	@codesign -s - $(DEPLOY_BIN) 2>/dev/null || true
	@echo "Deployed to $(DEPLOY_BIN)"

deploy-fast: build ## Deploy without quality gates
	@mkdir -p $(DEPLOY_DIR)/bin
	@if [ -f "$(DEPLOY_BIN)" ]; then cp "$(DEPLOY_BIN)" "$(DEPLOY_BIN).bak"; fi
	cp target/release/$(BINARY_NAME) $(DEPLOY_BIN)
	@codesign -s - $(DEPLOY_BIN) 2>/dev/null || true
	@echo "Deployed to $(DEPLOY_BIN) (fast)"

push: quality ## Quality gates + git push
	git push

clean: ## Clean build artifacts
	cargo clean
