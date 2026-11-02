# 🦀 soroban-xdr-proof-kit (v0.3.0)

[![Tests](https://img.shields.io/badge/Tests-8%2F8_Passing-2ea44f?logo=rust)](tests/proof_test.rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-000000?logo=rust)](Cargo.toml)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/soroban-xdr-proof-kit/commits/main)

**`soroban-xdr-proof-kit`** is a zero-dependency, zero-unsafe Rust & WebAssembly toolkit + CLI for **decoding binary Stellar `LedgerHeader` XDR frames (RFC 4506)**, computing **FIPS 180-4 SHA-256 cryptographic ancestry proofs**, and resolving **History Archive checkpoint boundaries (`64 * n - 1`)** offline without trusting centralized RPC servers.

> 🔗 **Production Heritage:** Extracted from real-world Stellar XDR & WebAssembly verification workflows, including my upstream merged contribution to **[Externalize-Labs/externalize#39 (`a927da3`)](https://github.com/Externalize-Labs/externalize/pull/39)** (*exporting `proveAncestor` to the WebAssembly verifier package*).

---

## ✨ Key Capabilities

1. **Pure-Rust FIPS 180-4 SHA-256 Engine (`sha256_digest`, `sha256_hex`):** Zero external crate dependencies; verified against official NIST cryptographic test vectors and compiles cleanly to `wasm32-unknown-unknown`.
2. **RFC 4506 Binary XDR Reader/Serializer (`XdrCursor`, `RawLedgerHeaderXdr`):** Decodes Big-Endian Stellar `LedgerHeader` wire frames, enforces strict 4-byte alignment zero-padding on variable-length opaque fields (`upgrades`), and parses RFC 5528 History Archive record marks.
3. **End-to-End Binary XDR Ancestry Verification (`verify_raw_xdr_header_chain`):** Hashes each `LedgerHeader` XDR frame directly with SHA-256 (`SHA256(raw_xdr_bytes)`) and verifies `header[i].previous_ledger_hash == SHA256(header[i - 1])` across contiguous `target_seq..=certified_seq` ranges.
4. **History Archive Checkpoint Calculator & CLI (`soroban-xdr-proof`):** Computes exact `ledger/xx/yy/zz/ledger-xxxxxxxx.xdr.gz` paths and `[start_seq, end_seq]` checkpoint bounds.

---

## 🚀 Library & CLI Quickstart

```rust
use soroban_xdr_proof_kit::{
    expected_archive_header_path, sha256_hex, verify_raw_xdr_header_chain, RawLedgerHeaderXdr,
};

let digest = sha256_hex(b"abc");
assert_eq!(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

let path = expected_archive_header_path(64_791_250);
assert_eq!(path, "ledger/03/dc/a2/ledger-03dca2ff.xdr.gz");
```

### CLI Usage

```bash
cargo run --bin soroban-xdr-proof -- checkpoint 64791250
# {"ledger_seq":64791250,"checkpoint_seq":64791295,"range_start":64791232,"range_end":64791295,"archive_path":"ledger/03/dc/a2/ledger-03dca2ff.xdr.gz"}

cargo run --bin soroban-xdr-proof -- prove-xdr-range 1000 1004
```

## 🧪 Running Tests

```bash
cargo test --all-targets --verbose
```

## 📄 License

Released under the [MIT License](LICENSE).

---

## 👤 Author & Verification Standard

Architected and maintained by **Khoa Phan (`@khoap1220-hue`)**.
> *"I architect and ship production-grade primitives across Rust, Go, TypeScript, and Python — powered by my proprietary multi-agent verification & triage pipeline, with every single line human-audited, race-tested (`go test -race`), and 100% GPG-signed."*
