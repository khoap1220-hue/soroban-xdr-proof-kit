//! # soroban-xdr-proof-kit
//!
//! Zero-dependency Rust & WebAssembly toolkit for:
//! 1. **FIPS 180-4 SHA-256 Cryptographic Hashing (`sha256_digest`, `sha256_hex`):**
//!    Pure-Rust SHA-256 compression engine requiring zero external crate dependencies.
//! 2. **RFC 4506 Binary XDR Framing & Stellar `LedgerHeader` Decoding (`XdrCursor`, `RawLedgerHeaderXdr`):**
//!    Deterministic Big-Endian XDR reader/writer with strict 4-byte zero-padding validation
//!    and RFC 5528 History Archive record-mark framing support.
//! 3. **Cryptographic Hash-Link Ancestry Verification (`verify_raw_xdr_header_chain`, `verify_ancestry_chain`):**
//!    Verifies unbroken `previous_ledger_hash == SHA256(parent_header_xdr)` chains from `certified_seq`
//!    down to `target_seq` and calculates canonical Stellar History Archive paths (`64 * n - 1`).

use std::fmt;

/// Standard Stellar history archive checkpoint frequency (every 64 ledgers).
pub const CHECKPOINT_FREQUENCY: u32 = 64;

/// FIPS 180-4 SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes).
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Structured errors returned during ledger proof and binary XDR verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    EmptyChain,
    TargetExceedsCertified { target_seq: u32, certified_seq: u32 },
    SequenceDiscontinuity { expected_seq: u32, actual_seq: u32 },
    HashMismatch { ledger_seq: u32, expected_hex: String, actual_hex: String },
    MissingHeader { ledger_seq: u32, expected_archive_path: String },
    InvalidDigestHex(String),
    XdrUnexpectedEof { needed: usize, remaining: usize },
    XdrInvalidPadding { offset: usize },
    XdrLengthOverflow { length: usize, max_allowed: usize },
    XdrTrailingBytes { remaining: usize },
    UnsupportedXdrExtension { field: &'static str, discriminant: u32 },
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
            ProofError::InvalidDigestHex(msg) => write!(f, "invalid hex input: {msg}"),
            ProofError::XdrUnexpectedEof { needed, remaining } => write!(
                f,
                "XDR buffer underflow: needed {needed} bytes, only {remaining} remaining"
            ),
            ProofError::XdrInvalidPadding { offset } => write!(
                f,
                "RFC 4506 XDR violation: non-zero alignment padding byte at offset {offset}"
            ),
            ProofError::XdrLengthOverflow { length, max_allowed } => write!(
                f,
                "XDR variable opaque length {length} exceeds maximum allowed {max_allowed}"
            ),
            ProofError::XdrTrailingBytes { remaining } => write!(
                f,
                "XDR frame contains {remaining} unexpected trailing bytes"
            ),
            ProofError::UnsupportedXdrExtension { field, discriminant } => write!(
                f,
                "unsupported XDR union discriminant {discriminant} on {field}"
            ),
        }
    }
}

impl std::error::Error for ProofError {}

/// Computes the FIPS 180-4 SHA-256 32-byte digest of `data`.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Encodes a byte slice as a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes an arbitrary even-length hex string into raw bytes.
pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, ProofError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.len() % 2 != 0 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProofError::InvalidDigestHex(format!(
            "expected non-empty even-length hex string, got length {}",
            trimmed.len()
        )));
    }
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in 0..(bytes.len() / 2) {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Parses a 64-character hex string into a 32-byte array.
pub fn hex_to_hash32(input: &str) -> Result<[u8; 32], ProofError> {
    let norm = normalize_sha256_hex(input)?;
    let raw = hex_to_bytes(&norm)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Computes the lowercase 64-character SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    bytes_to_hex(&sha256_digest(data))
}

/// Deterministic RFC 4506 Big-Endian binary XDR reader with 4-byte alignment checks.
#[derive(Debug, Clone)]
pub struct XdrCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrCursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProofError> {
        if self.remaining() < n {
            return Err(ProofError::XdrUnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_u32(&mut self) -> Result<u32, ProofError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_i32(&mut self) -> Result<i32, ProofError> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, ProofError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_i64(&mut self) -> Result<i64, ProofError> {
        let b = self.take(8)?;
        Ok(i64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_hash32(&mut self) -> Result<[u8; 32], ProofError> {
        let b = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    /// Reads an RFC 4506 variable-length opaque byte array (`length: u32` + payload + 0..3 zero padding bytes).
    pub fn read_var_opaque(&mut self, max_len: usize) -> Result<Vec<u8>, ProofError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(ProofError::XdrLengthOverflow {
                length: len,
                max_allowed: max_len,
            });
        }
        let payload = self.take(len)?.to_vec();
        let pad_len = (4 - (len % 4)) % 4;
        if pad_len > 0 {
            let pad_start = self.pos;
            let pad = self.take(pad_len)?;
            for (idx, &byte) in pad.iter().enumerate() {
                if byte != 0 {
                    return Err(ProofError::XdrInvalidPadding {
                        offset: pad_start + idx,
                    });
                }
            }
        }
        Ok(payload)
    }

    /// Reads an RFC 5528 Record Marking 4-byte header (`last_fragment: bool`, `record_byte_length: u32`).
    pub fn read_rfc5528_record_mark(&mut self) -> Result<(bool, u32), ProofError> {
        let raw = self.read_u32()?;
        let is_last = (raw & 0x8000_0000) != 0;
        let byte_len = raw & 0x7fff_ffff;
        Ok((is_last, byte_len))
    }

    pub fn ensure_complete(&self) -> Result<(), ProofError> {
        if self.remaining() != 0 {
            return Err(ProofError::XdrTrailingBytes {
                remaining: self.remaining(),
            });
        }
        Ok(())
    }
}

/// Decoded representation of a canonical Stellar `LedgerHeader` binary XDR structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLedgerHeaderXdr {
    pub ledger_version: u32,
    pub previous_ledger_hash: [u8; 32],
    pub tx_set_hash: [u8; 32],
    pub close_time: u64,
    pub upgrades_opaque: Vec<u8>,
    pub scp_value_ext: u32,
    pub tx_set_result_hash: [u8; 32],
    pub bucket_list_hash: [u8; 32],
    pub ledger_seq: u32,
    pub total_coins: i64,
    pub fee_pool: i64,
    pub inflation_seq: u32,
    pub id_pool: u64,
    pub base_fee: u32,
    pub base_reserve: u32,
    pub max_tx_set_size: u32,
    pub skip_list: [[u8; 32]; 4],
    pub ext: u32,
}

impl RawLedgerHeaderXdr {
    /// Serializes this `LedgerHeader` into canonical RFC 4506 Big-Endian XDR wire bytes.
    pub fn to_xdr_bytes(&self) -> Result<Vec<u8>, ProofError> {
        if self.upgrades_opaque.len() > 65_536 {
            return Err(ProofError::XdrLengthOverflow {
                length: self.upgrades_opaque.len(),
                max_allowed: 65_536,
            });
        }
        if self.scp_value_ext > 1 {
            return Err(ProofError::UnsupportedXdrExtension {
                field: "StellarValue.ext",
                discriminant: self.scp_value_ext,
            });
        }
        if self.ext > 1 {
            return Err(ProofError::UnsupportedXdrExtension {
                field: "LedgerHeader.ext",
                discriminant: self.ext,
            });
        }

        let mut out = Vec::with_capacity(340 + self.upgrades_opaque.len());
        out.extend_from_slice(&self.ledger_version.to_be_bytes());
        out.extend_from_slice(&self.previous_ledger_hash);
        out.extend_from_slice(&self.tx_set_hash);
        out.extend_from_slice(&self.close_time.to_be_bytes());

        let upg_len = self.upgrades_opaque.len() as u32;
        out.extend_from_slice(&upg_len.to_be_bytes());
        out.extend_from_slice(&self.upgrades_opaque);
        let pad_len = (4 - (self.upgrades_opaque.len() % 4)) % 4;
        for _ in 0..pad_len {
            out.push(0u8);
        }

        out.extend_from_slice(&self.scp_value_ext.to_be_bytes());
        if self.scp_value_ext == 1 {
            // STELLAR_VALUE_SIGNED: PublicKey (PUBLIC_KEY_TYPE_ED25519 = 0 + 32B key) + Signature (64B)
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&[0u8; 32]);
            out.extend_from_slice(&64u32.to_be_bytes());
            out.extend_from_slice(&[0u8; 64]);
        }

        out.extend_from_slice(&self.tx_set_result_hash);
        out.extend_from_slice(&self.bucket_list_hash);
        out.extend_from_slice(&self.ledger_seq.to_be_bytes());
        out.extend_from_slice(&self.total_coins.to_be_bytes());
        out.extend_from_slice(&self.fee_pool.to_be_bytes());
        out.extend_from_slice(&self.inflation_seq.to_be_bytes());
        out.extend_from_slice(&self.id_pool.to_be_bytes());
        out.extend_from_slice(&self.base_fee.to_be_bytes());
        out.extend_from_slice(&self.base_reserve.to_be_bytes());
        out.extend_from_slice(&self.max_tx_set_size.to_be_bytes());
        for skip in &self.skip_list {
            out.extend_from_slice(skip);
        }
        out.extend_from_slice(&self.ext.to_be_bytes());
        if self.ext == 1 {
            // LedgerHeaderExtensionV1: flags (u32) + ext union discriminant 0 (u32)
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        Ok(out)
    }

    /// Decodes a canonical Stellar `LedgerHeader` from RFC 4506 Big-Endian XDR bytes.
    /// Supports both `STELLAR_VALUE_BASIC` (`0`) and `STELLAR_VALUE_SIGNED` (`1`), as well
    /// as `LedgerHeader.ext == 0` and `LedgerHeaderExtensionV1` (`ext == 1`).
    pub fn from_xdr_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let mut cur = XdrCursor::new(bytes);
        let ledger_version = cur.read_u32()?;
        let previous_ledger_hash = cur.read_hash32()?;
        let tx_set_hash = cur.read_hash32()?;
        let close_time = cur.read_u64()?;
        let upgrades_opaque = cur.read_var_opaque(65_536)?;
        let scp_value_ext = cur.read_u32()?;
        match scp_value_ext {
            0 => {}
            1 => {
                // STELLAR_VALUE_SIGNED: NodeID (PublicKey) + Signature (opaque<64>)
                let pk_type = cur.read_u32()?;
                if pk_type != 0 {
                    return Err(ProofError::UnsupportedXdrExtension {
                        field: "LedgerCloseValueSignature.nodeID",
                        discriminant: pk_type,
                    });
                }
                let _node_ed25519 = cur.read_hash32()?;
                let _sig = cur.read_var_opaque(64)?;
            }
            other => {
                return Err(ProofError::UnsupportedXdrExtension {
                    field: "StellarValue.ext",
                    discriminant: other,
                });
            }
        }
        let tx_set_result_hash = cur.read_hash32()?;
        let bucket_list_hash = cur.read_hash32()?;
        let ledger_seq = cur.read_u32()?;
        let total_coins = cur.read_i64()?;
        let fee_pool = cur.read_i64()?;
        let inflation_seq = cur.read_u32()?;
        let id_pool = cur.read_u64()?;
        let base_fee = cur.read_u32()?;
        let base_reserve = cur.read_u32()?;
        let max_tx_set_size = cur.read_u32()?;
        let skip_list = [
            cur.read_hash32()?,
            cur.read_hash32()?,
            cur.read_hash32()?,
            cur.read_hash32()?,
        ];
        let ext = cur.read_u32()?;
        match ext {
            0 => {}
            1 => {
                // LedgerHeaderExtensionV1: uint32 flags + ext union (discriminant 0)
                let _flags = cur.read_u32()?;
                let v1_ext = cur.read_u32()?;
                if v1_ext != 0 {
                    return Err(ProofError::UnsupportedXdrExtension {
                        field: "LedgerHeaderExtensionV1.ext",
                        discriminant: v1_ext,
                    });
                }
            }
            other => {
                return Err(ProofError::UnsupportedXdrExtension {
                    field: "LedgerHeader.ext",
                    discriminant: other,
                });
            }
        }
        cur.ensure_complete()?;

        Ok(Self {
            ledger_version,
            previous_ledger_hash,
            tx_set_hash,
            close_time,
            upgrades_opaque,
            scp_value_ext,
            tx_set_result_hash,
            bucket_list_hash,
            ledger_seq,
            total_coins,
            fee_pool,
            inflation_seq,
            id_pool,
            base_fee,
            base_reserve,
            max_tx_set_size,
            skip_list,
            ext,
        })
    }

    /// Computes the authentic FIPS 180-4 SHA-256 digest over this header's canonical XDR bytes.
    pub fn compute_header_hash(&self) -> Result<[u8; 32], ProofError> {
        let raw = self.to_xdr_bytes()?;
        Ok(sha256_digest(&raw))
    }

    /// Converts this binary header into a `LedgerHeaderLink` with cryptographically derived `header_hash_hex`.
    pub fn to_header_link(&self) -> Result<LedgerHeaderLink, ProofError> {
        let digest = self.compute_header_hash()?;
        Ok(LedgerHeaderLink {
            ledger_seq: self.ledger_seq,
            previous_ledger_hash_hex: bytes_to_hex(&self.previous_ledger_hash),
            header_hash_hex: bytes_to_hex(&digest),
            tx_set_result_hash_hex: bytes_to_hex(&self.tx_set_result_hash),
        })
    }
}

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
/// containing the given `ledger_seq` using overflow-safe 64-bit arithmetic.
pub fn checkpoint_for_ledger(ledger_seq: u32) -> u32 {
    let freq = CHECKPOINT_FREQUENCY as u64;
    let bucket = ((ledger_seq as u64) / freq) + 1;
    let chk = (bucket * freq) - 1;
    chk.min(u32::MAX as u64) as u32
}

/// Computes the inclusive `[start_seq, end_seq]` ledger range covered by the checkpoint
/// containing `ledger_seq`.
pub fn checkpoint_bounds_for_ledger(ledger_seq: u32) -> (u32, u32) {
    let end_seq = checkpoint_for_ledger(ledger_seq);
    let start_seq = if end_seq < CHECKPOINT_FREQUENCY {
        1
    } else {
        end_seq - CHECKPOINT_FREQUENCY + 1
    };
    (start_seq, end_seq)
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

/// Decodes raw binary `LedgerHeader` XDR frames, computes each frame's FIPS 180-4 SHA-256 hash
/// directly from its wire bytes, and verifies the unbroken hash-link ancestry chain.
pub fn verify_raw_xdr_header_chain(
    raw_headers: &[Vec<u8>],
    target_seq: u32,
    certified_seq: u32,
) -> Result<VerifiedAncestryProof, ProofError> {
    if target_seq > certified_seq {
        return Err(ProofError::TargetExceedsCertified {
            target_seq,
            certified_seq,
        });
    }
    if raw_headers.is_empty() {
        return Err(ProofError::EmptyChain);
    }

    let mut links = Vec::with_capacity(raw_headers.len());
    for raw in raw_headers {
        let decoded = RawLedgerHeaderXdr::from_xdr_bytes(raw)?;
        let actual_hash = bytes_to_hex(&sha256_digest(raw));
        links.push(LedgerHeaderLink {
            ledger_seq: decoded.ledger_seq,
            previous_ledger_hash_hex: bytes_to_hex(&decoded.previous_ledger_hash),
            header_hash_hex: actual_hash,
            tx_set_result_hash_hex: bytes_to_hex(&decoded.tx_set_result_hash),
        });
    }
    verify_ancestry_chain(&links, target_seq, certified_seq)
}

/// Verifies an unbroken backward hash-link chain from `certified_seq` down to `target_seq`.
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
    sorted.dedup_by(|a, b| {
        a.ledger_seq == b.ledger_seq
            && a.header_hash_hex.eq_ignore_ascii_case(&b.header_hash_hex)
            && a.previous_ledger_hash_hex
                .eq_ignore_ascii_case(&b.previous_ledger_hash_hex)
    });

    let expected_len = ((certified_seq as u64) - (target_seq as u64) + 1) as usize;
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
        let _ = normalize_sha256_hex(&current.header_hash_hex)?;
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

/// Verifies a binary SHA-256 Merkle inclusion branch (`side = false` for left sibling, `true` for right sibling).
pub fn verify_merkle_branch(leaf_hash: &[u8; 32], branch: &[([u8; 32], bool)], expected_root: &[u8; 32]) -> bool {
    let mut acc = *leaf_hash;
    for (sibling, is_right_sibling) in branch {
        let mut buf = [0u8; 64];
        if *is_right_sibling {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&acc);
        }
        acc = sha256_digest(&buf);
    }
    &acc == expected_root
}
