# dobby — dev commands. Run `just --list` for all recipes.

set shell := ["bash", "-uc"]
set dotenv-load := true

# default recipe lists every task
default:
    @just --list

# ── build & check ─────────────────────────────────────────

# fast compile check across the workspace
check:
    cargo check --workspace --all-targets

# build all crates (debug)
build:
    cargo build --workspace

# build release binary
build-release:
    cargo build --release --workspace

# run the full test suite
test:
    cargo test --workspace --all-targets

# generate (but don't open) rustdoc for all crates
doc:
    cargo doc --workspace --no-deps

# ── formatting & lints ────────────────────────────────────

# apply rustfmt to the workspace (nightly required for unstable knobs in
# rustfmt.toml: imports_granularity, group_imports, wrap_comments,
# format_code_in_doc_comments)
fmt:
    cargo +nightly fmt --all

# check formatting without modifying (CI)
fmt-check:
    cargo +nightly fmt --all -- --check

# run clippy with -D warnings
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# lint the proto files (requires `buf` on PATH)
buf-lint:
    buf lint

# check proto backwards compatibility against the latest git tag
# (no-op until a tag exists — safe to call on a fresh repo)
buf-breaking:
    @if git describe --tags --abbrev=0 >/dev/null 2>&1; then \
        buf breaking --against '.git#tag=latest' ; \
    else \
        echo "no git tag yet — skipping buf breaking check" ; \
    fi

# ── composite / CI ────────────────────────────────────────

# everything CI runs, in one shot
ci: fmt-check clippy check test buf-lint buf-breaking

# pre-commit subset — fast feedback before commit
pre-commit: fmt clippy check

# ── dev run ───────────────────────────────────────────────

# show the full dobby CLI surface
help:
    cargo run --quiet -- --help

# run dobby keeper start (debug mode, tracing=info)
keeper-start:
    RUST_LOG=info cargo run --quiet -- keeper start

# run dobby elf start
elf-start:
    RUST_LOG=info cargo run --quiet -- elf start

# ── maintenance ───────────────────────────────────────────

# clean cargo target
clean:
    cargo clean

# update Cargo.lock (review the diff!)
update:
    cargo update

# install dev tools referenced by this justfile
install-dev-tools:
    cargo install just cargo-audit cargo-deny cargo-machete cargo-udeps cargo-semver-checks typos-cli
    @echo
    @echo "Also install 'buf' manually — see https://buf.build/docs/installation"

# audit dependencies for known CVEs
audit:
    cargo audit

# check licences + bans (uses deny.toml)
deny:
    cargo deny check

# detect unused dependencies (fast, lockfile-free)
machete:
    cargo machete

# spell-check identifiers + comments (uses typos.toml)
typos:
    typos

# detect public-API breaking changes (skips publish=false crates)
semver:
    cargo semver-checks check-release --workspace || true

# detect unused dependencies via real build graph (nightly)
udeps:
    cargo +nightly udeps --workspace --all-targets
