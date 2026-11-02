//! # soroban-xdr-proof-kit
//!
//! Deterministic Rust & WebAssembly utilities for verifying Stellar ledger header
//! hash-link ancestry chains, computing history archive checkpoint ranges, and
//! validating Soroban contract interface compatibility without external RPC trust.

use std::fmt;

/// Standard Stellar history archive checkpoint frequency (every 64 ledgers).
pub const CHECKPOINT_FREQUENCY: u32 = 64;

/// Structured errors returned during ledger proof and XDR header verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    EmptyChain,
    TargetExceedsCertified { target_seq: u32, certified_seq: u32 },
    SequenceDiscontinuity { expected_seq: u32, actual_seq: u32 },
    HashMismatch { ledger_seq: u32, expected_hex: String, actual_hex: String },
    MissingHeader { ledger_seq: u32, expected_archive_path: String },
    InvalidDigestHex(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::EmptyChain => write!(f, "header chain cannot be empty"),
            ProofError::TargetExceedsCertified { target_seq, certified_seq } => write!(
                f,
                "target sequence ({target_seq}) exceeds certified sequence ({certified_seq})"
            ),
            ProofError::SequenceDiscontinuity { expected_seq, actual_seq } => write!(
                f,
                "ledger sequence discontinuity: expected {expected_seq}, got {actual_seq}"
            ),
            ProofError::HashMismatch { ledger_seq, expected_hex, actual_hex } => write!(
                f,
                "cryptographic hash mismatch at ledger {ledger_seq}: expected {expected_hex}, got {actual_hex}"
            ),
            ProofError::MissingHeader { ledger_seq, expected_archive_path } => write!(
                f,
                "missing ledger header {ledger_seq} (expected archive object: {expected_archive_path})"
            ),
            ProofError::InvalidDigestHex(msg) => write!(f, "invalid 32-byte hex digest: {msg}"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Minimal representation of a decoded Stellar LedgerHeader XDR link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerHeaderLink {
    pub ledger_seq: u32,
    pub previous_ledger_hash_hex: String,
    pub header_hash_hex: String,
    pub tx_set_result_hash_hex: String,
}

/// Verified cryptographic ancestry proof result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAncestryProof {
    pub target_seq: u32,
    pub certified_seq: u32,
    pub target_hash_hex: String,
    pub certified_hash_hex: String,
    pub chain_length: usize,
}

/// Computes the canonical Stellar history archive checkpoint sequence (`64 * n - 1`)
/// containing the given `ledger_seq`.
pub fn checkpoint_for_ledger(ledger_seq: u32) -> u32 {
    let bucket = (ledger_seq / CHECKPOINT_FREQUENCY) + 1;
    (bucket * CHECKPOINT_FREQUENCY) - 1
}

/// Formats the canonical Stellar History Archive path (`ledger/xx/yy/zz/ledger-xxxxxxxx.xdr.gz`)
/// for a given ledger sequence.
pub fn expected_archive_header_path(ledger_seq: u32) -> String {
    let chk = checkpoint_for_ledger(ledger_seq);
    let hex_str = format!("{chk:08x}");
    let p1 = &hex_str[0..2];
    let p2 = &hex_str[2..4];
    let p3 = &hex_str[4..6];
    format!("ledger/{p1}/{p2}/{p3}/ledger-{hex_str}.xdr.gz")
}

/// Validates a 64-character lowercase/uppercase SHA-256 hex digest.
pub fn normalize_sha256_hex(input: &str) -> Result<String, ProofError> {
    let trimmed = input.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProofError::InvalidDigestHex(format!(
            "expected 64 hex chars, got length {}",
            trimmed.len()
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Verifies an unbroken backward hash-link chain from `certified_seq` down to `target_seq`.
///
/// Mirrors the exact verification semantics required by both CLI and WebAssembly (`proveAncestor`)
/// verifiers:
/// 1. `target_seq <= certified_seq`
/// 2. Every consecutive link satisfies `header[i].previous_ledger_hash == header[i - 1].header_hash`
/// 3. Sequence numbers are strictly contiguous (`target_seq..=certified_seq`).
pub fn verify_ancestry_chain(
    headers: &[LedgerHeaderLink],
    target_seq: u32,
    certified_seq: u32,
) -> Result<VerifiedAncestryProof, ProofError> {
    if target_seq > certified_seq {
        return Err(ProofError::TargetExceedsCertified {
            target_seq,
            certified_seq,
        });
    }
    if headers.is_empty() {
        return Err(ProofError::EmptyChain);
    }

    let mut sorted = headers.to_vec();
    sorted.sort_by_key(|h| h.ledger_seq);
    sorted.retain(|h| h.ledger_seq >= target_seq && h.ledger_seq <= certified_seq);

    let expected_len = (certified_seq - target_seq + 1) as usize;
    if sorted.len() != expected_len {
        for seq in target_seq..=certified_seq {
            if sorted.binary_search_by_key(&seq, |h| h.ledger_seq).is_err() {
                return Err(ProofError::MissingHeader {
                    ledger_seq: seq,
                    expected_archive_path: expected_archive_header_path(seq),
                });
            }
        }
    }

    for idx in 0..sorted.len() {
        let expected_seq = target_seq + (idx as u32);
        let current = &sorted[idx];
        if current.ledger_seq != expected_seq {
            return Err(ProofError::SequenceDiscontinuity {
                expected_seq,
                actual_seq: current.ledger_seq,
            });
        }
        let curr_hash = normalize_sha256_hex(&current.header_hash_hex)?;
        let _ = normalize_sha256_hex(&current.previous_ledger_hash_hex)?;

        if idx > 0 {
            let prev = &sorted[idx - 1];
            let prev_hash = normalize_sha256_hex(&prev.header_hash_hex)?;
            let claimed_prev = normalize_sha256_hex(&current.previous_ledger_hash_hex)?;
            if claimed_prev != prev_hash {
                return Err(ProofError::HashMismatch {
                    ledger_seq: current.ledger_seq,
                    expected_hex: prev_hash,
                    actual_hex: claimed_prev,
                });
            }
        }
        let _ = curr_hash;
    }

    let first = &sorted[0];
    let last = &sorted[sorted.len() - 1];
    Ok(VerifiedAncestryProof {
        target_seq,
        certified_seq,
        target_hash_hex: normalize_sha256_hex(&first.header_hash_hex)?,
        certified_hash_hex: normalize_sha256_hex(&last.header_hash_hex)?,
        chain_length: sorted.len(),
    })
}
