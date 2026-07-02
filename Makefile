SHELL := /bin/sh
.DEFAULT_GOAL := help

CARGO ?= cargo
CARGO_HOME ?= $(CURDIR)/.cargo-home
CARGO_ENV := CARGO_HOME="$(CARGO_HOME)"

.PHONY: help fmt check clippy lint build build-release test test-cli test-e2e audit clean install

help:
	@printf '%s\n' 'Available targets:'
	@printf '  %-18s %s\n' 'make fmt' 'Check Rust formatting'
	@printf '  %-18s %s\n' 'make check' 'Type-check all targets'
	@printf '  %-18s %s\n' 'make clippy' 'Run clippy with warnings as errors'
	@printf '  %-18s %s\n' 'make lint' 'Run formatting, check, and clippy'
	@printf '  %-18s %s\n' 'make build' 'Build the debug binary'
	@printf '  %-18s %s\n' 'make build-release' 'Build the optimized release binary'
	@printf '  %-18s %s\n' 'make test' 'Run the full test suite'
	@printf '  %-18s %s\n' 'make test-e2e' 'Run mock end-to-end tests'
	@printf '  %-18s %s\n' 'make audit' 'Run cargo-audit when installed'
	@printf '  %-18s %s\n' 'make clean' 'Remove Cargo build output'

fmt:
	$(CARGO_ENV) $(CARGO) fmt --check

check:
	$(CARGO_ENV) $(CARGO) check --all-targets

clippy:
	$(CARGO_ENV) $(CARGO) clippy --all-targets -- -D warnings

lint: fmt check clippy

build:
	$(CARGO_ENV) $(CARGO) build --locked

build-release:
	$(CARGO_ENV) $(CARGO) build --release --locked

test:
	$(CARGO_ENV) $(CARGO) test --locked

test-cli:
	$(CARGO_ENV) $(CARGO) test --test cli

test-e2e:
	$(CARGO_ENV) $(CARGO) test --test e2e_mock

audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		$(CARGO_ENV) cargo-audit audit; \
	elif [ -x target/cargo-tools/bin/cargo-audit ]; then \
		target/cargo-tools/bin/cargo-audit audit; \
	else \
		printf '%s\n' 'cargo-audit is not installed; install it with cargo install cargo-audit.' >&2; \
		exit 127; \
	fi

install:
	$(CARGO) install --path . --locked

clean:
	$(CARGO_ENV) $(CARGO) clean
