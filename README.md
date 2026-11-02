# 🦀 soroban-xdr-proof-kit

[![Tests](https://img.shields.io/badge/Tests-5%2F5_Passing-2ea44f?logo=rust)](tests/proof_test.rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-000000?logo=rust)](Cargo.toml)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/soroban-xdr-proof-kit/commits/main)

**`soroban-xdr-proof-kit`** is a lightweight, zero-unsafe Rust & WebAssembly-ready library for verifying **Stellar `LedgerHeader` cryptographic hash-link chains**, computing **History Archive checkpoint boundaries (`64 * n - 1`)**, and diagnosing missing archive objects offline without trusting centralized RPC providers.

> 🔗 **Production Heritage:** Extracted from real-world Stellar XDR & WebAssembly verification workflows, including our upstream merged contribution to **[Externalize-Labs/externalize#39 (`a927da3`)](https://github.com/Externalize-Labs/externalize/pull/39)** (*exporting `proveAncestor` to the WebAssembly verifier package*).

---

## ✨ Features

- **Unbroken Hash-Link Ancestry Verification (`verify_ancestry_chain`):** Validates contiguous `target_seq..=certified_seq` chains and asserts `previous_ledger_hash == parent.header_hash` across every hop.
- **History Archive Checkpoint Math (`checkpoint_for_ledger` & `expected_archive_header_path`):** Computes exact Stellar archive object paths (`ledger/xx/yy/zz/ledger-xxxxxxxx.xdr.gz`) when diagnosing missing ledger headers.
- **WebAssembly & CLI Parity:** Enforces identical `TargetExceedsCertified` and `MissingHeader` error semantics across native Rust CLIs and browser `wasm-bindgen` targets.

---

## 🚀 Quickstart

```rust
use soroban_xdr_proof_kit::{
    checkpoint_for_ledger, expected_archive_header_path, verify_ancestry_chain, LedgerHeaderLink,
};

let path = expected_archive_header_path(64_791_250);
assert_eq!(path, "ledger/03/dc/a2/ledger-03dca2ff.xdr.gz");
```

## 🧪 Running Tests

```bash
cargo test --all-targets --verbose
```

## 📄 License

Released under the [MIT License](LICENSE) — free for community and commercial use.
