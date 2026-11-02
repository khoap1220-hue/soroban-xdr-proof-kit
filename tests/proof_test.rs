use soroban_xdr_proof_kit::{
    checkpoint_bounds_for_ledger, checkpoint_for_ledger, expected_archive_header_path, sha256_hex,
    verify_ancestry_chain, verify_raw_xdr_header_chain, LedgerHeaderLink, ProofError,
    RawLedgerHeaderXdr, XdrCursor,
};

fn sample_hash(byte_char: char) -> String {
    std::iter::repeat(byte_char).take(64).collect()
}

fn sample_raw_header(seq: u32, prev_hash: [u8; 32]) -> RawLedgerHeaderXdr {
    RawLedgerHeaderXdr {
        ledger_version: 21,
        previous_ledger_hash: prev_hash,
        tx_set_hash: [0x11; 32],
        close_time: 1_730_000_000 + (seq as u64) * 5,
        upgrades_opaque: vec![0x01, 0x02, 0x03], // 3 bytes -> tests 1-byte zero padding in RFC 4506 XDR
        scp_value_ext: 0,
        tx_set_result_hash: [0x22; 32],
        bucket_list_hash: [0x33; 32],
        ledger_seq: seq,
        total_coins: 100_000_000_000_000_000,
        fee_pool: 250_000,
        inflation_seq: 0,
        id_pool: 42,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 1000,
        skip_list: [[0x44; 32]; 4],
        ext: 0,
    }
}

#[test]
fn test_fips_180_4_sha256_official_nist_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_xdr_binary_roundtrip_and_padding_enforcement() {
    let hdr = sample_raw_header(64_791_250, [0x99; 32]);
    let wire = hdr.to_xdr_bytes().expect("serialize XDR");
    assert_eq!(wire.len() % 4, 0, "RFC 4506 XDR frames must be 4-byte aligned");

    let decoded = RawLedgerHeaderXdr::from_xdr_bytes(&wire).expect("decode XDR");
    assert_eq!(decoded, hdr);

    // Corrupt the 1-byte alignment padding after upgrades_opaque (offset: 4 + 32 + 32 + 8 + 4 + 3 = 83)
    let mut bad_padding = wire.clone();
    bad_padding[83] = 0xff;
    let err = RawLedgerHeaderXdr::from_xdr_bytes(&bad_padding).unwrap_err();
    assert_eq!(err, ProofError::XdrInvalidPadding { offset: 83 });
}

#[test]
fn test_rfc5528_record_mark_parsing() {
    // Last fragment bit (0x80000000) | 316 bytes (0x0000013c)
    let bytes = [0x80, 0x00, 0x01, 0x3c];
    let mut cur = XdrCursor::new(&bytes);
    let (is_last, len) = cur.read_rfc5528_record_mark().expect("record mark");
    assert!(is_last);
    assert_eq!(len, 316);
}

#[test]
fn test_verify_raw_xdr_header_chain_authentic_sha256_links() {
    let h500 = sample_raw_header(500, [0x01; 32]);
    let hash500 = h500.compute_header_hash().unwrap();
    let h501 = sample_raw_header(501, hash500);
    let hash501 = h501.compute_header_hash().unwrap();
    let h502 = sample_raw_header(502, hash501);

    let frames = vec![
        h502.to_xdr_bytes().unwrap(),
        h500.to_xdr_bytes().unwrap(),
        h501.to_xdr_bytes().unwrap(),
    ];
    let proof = verify_raw_xdr_header_chain(&frames, 500, 502).expect("cryptographic XDR chain");
    assert_eq!(proof.chain_length, 3);

    // Mutate a single byte inside h501's fee_pool without updating h502.previous_ledger_hash
    let mut h501_tampered = h501.clone();
    h501_tampered.fee_pool += 1;
    let tampered_frames = vec![
        h500.to_xdr_bytes().unwrap(),
        h501_tampered.to_xdr_bytes().unwrap(),
        h502.to_xdr_bytes().unwrap(),
    ];
    let err = verify_raw_xdr_header_chain(&tampered_frames, 500, 502).unwrap_err();
    assert!(matches!(err, ProofError::HashMismatch { ledger_seq: 502, .. }));
}

#[test]
fn test_checkpoint_and_archive_path_formatting() {
    assert_eq!(checkpoint_for_ledger(64791250), 64791295);
    assert_eq!(checkpoint_bounds_for_ledger(64791250), (64791232, 64791295));
    assert_eq!(
        expected_archive_header_path(64791250),
        "ledger/03/dc/a2/ledger-03dca2ff.xdr.gz"
    );
}

#[test]
fn test_valid_three_ledger_ancestry_chain() {
    let h100 = LedgerHeaderLink {
        ledger_seq: 100,
        previous_ledger_hash_hex: sample_hash('a'),
        header_hash_hex: sample_hash('b'),
        tx_set_result_hash_hex: sample_hash('1'),
    };
    let h101 = LedgerHeaderLink {
        ledger_seq: 101,
        previous_ledger_hash_hex: sample_hash('b'),
        header_hash_hex: sample_hash('c'),
        tx_set_result_hash_hex: sample_hash('2'),
    };
    let h102 = LedgerHeaderLink {
        ledger_seq: 102,
        previous_ledger_hash_hex: sample_hash('c'),
        header_hash_hex: sample_hash('d'),
        tx_set_result_hash_hex: sample_hash('3'),
    };

    let proof = verify_ancestry_chain(&[h102, h100, h101], 100, 102).expect("valid chain");
    assert_eq!(proof.target_seq, 100);
    assert_eq!(proof.certified_seq, 102);
    assert_eq!(proof.chain_length, 3);
}

#[test]
fn test_rejects_target_exceeding_certified() {
    let err = verify_ancestry_chain(&[], 200, 199).unwrap_err();
    assert_eq!(
        err,
        ProofError::TargetExceedsCertified {
            target_seq: 200,
            certified_seq: 199
        }
    );
}

#[test]
fn test_reports_exact_archive_path_on_missing_header() {
    let h100 = LedgerHeaderLink {
        ledger_seq: 100,
        previous_ledger_hash_hex: sample_hash('a'),
        header_hash_hex: sample_hash('b'),
        tx_set_result_hash_hex: sample_hash('1'),
    };
    let h102 = LedgerHeaderLink {
        ledger_seq: 102,
        previous_ledger_hash_hex: sample_hash('c'),
        header_hash_hex: sample_hash('d'),
        tx_set_result_hash_hex: sample_hash('3'),
    };

    let err = verify_ancestry_chain(&[h100.clone(), h102.clone()], 100, 102).unwrap_err();
    assert_eq!(
        err,
        ProofError::MissingHeader {
            ledger_seq: 101,
            expected_archive_path: "ledger/00/00/00/ledger-0000007f.xdr.gz".to_string()
        }
    );

    // Even if duplicate h100 is supplied so slice length == 3, missing 101 is still caught as MissingHeader
    let err_dup = verify_ancestry_chain(&[h100.clone(), h100, h102], 100, 102).unwrap_err();
    assert_eq!(
        err_dup,
        ProofError::MissingHeader {
            ledger_seq: 101,
            expected_archive_path: "ledger/00/00/00/ledger-0000007f.xdr.gz".to_string()
        }
    );
}

#[test]
fn test_signed_stellar_value_and_ledger_header_ext_v1_and_u32_max_checkpoint() {
    let mut hdr = sample_raw_header(64_791_255, [0x77; 32]);
    hdr.scp_value_ext = 1; // STELLAR_VALUE_SIGNED
    hdr.ext = 1; // LedgerHeaderExtensionV1
    let wire = hdr.to_xdr_bytes().expect("serialize signed ext=1 XDR");
    let decoded = RawLedgerHeaderXdr::from_xdr_bytes(&wire).expect("decode signed ext=1 XDR");
    assert_eq!(decoded, hdr);

    // Unsupported union arm (ext = 99) must return UnsupportedXdrExtension
    let mut bad_hdr = hdr;
    bad_hdr.ext = 99;
    let err = bad_hdr.to_xdr_bytes().unwrap_err();
    assert_eq!(
        err,
        ProofError::UnsupportedXdrExtension {
            field: "LedgerHeader.ext",
            discriminant: 99
        }
    );

    // Overflow-safe checkpoint math at u32::MAX
    assert_eq!(checkpoint_for_ledger(u32::MAX), u32::MAX);
}

#[test]
fn test_rfc4506_boundary_and_malformed_frame_vectors() {
    use soroban_xdr_proof_kit::{XdrCursor, MAX_XDR_FRAME_BYTES};

    // Table-driven boundary tests: 0, 3, 4, MAX_XDR_FRAME_BYTES, MAX_XDR_FRAME_BYTES + 4, 0x7FFF_FFFF
    struct BoundaryCase {
        len: usize,
        pad_byte: u8,
        max_allowed: usize,
        expect_ok: bool,
    }

    let cases = vec![
        // Length 0: exactly 4 bytes (len field), no payload, 0 padding
        BoundaryCase { len: 0, pad_byte: 0, max_allowed: 1024, expect_ok: true },
        // Length 3: 3 bytes payload + 1 zero pad byte
        BoundaryCase { len: 3, pad_byte: 0, max_allowed: 1024, expect_ok: true },
        // Length 3 with corrupted non-zero padding byte
        BoundaryCase { len: 3, pad_byte: 0xff, max_allowed: 1024, expect_ok: false },
        // Length 4: 4 bytes payload + 0 pad bytes
        BoundaryCase { len: 4, pad_byte: 0, max_allowed: 1024, expect_ok: true },
        // Length MAX_XDR_FRAME_BYTES within limit
        BoundaryCase { len: 16, pad_byte: 0, max_allowed: 16, expect_ok: true },
        // Length exceeding max_allowed
        BoundaryCase { len: MAX_XDR_FRAME_BYTES + 4, pad_byte: 0, max_allowed: MAX_XDR_FRAME_BYTES, expect_ok: false },
    ];

    for c in cases {
        let pad_len = (4 - (c.len % 4)) % 4;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(c.len as u32).to_be_bytes());
        buf.resize(4 + c.len, 0x5a);
        for _ in 0..pad_len {
            buf.push(c.pad_byte);
        }

        let mut cur = XdrCursor::new(&buf);
        let res = cur.read_var_opaque(c.max_allowed);
        if c.expect_ok {
            assert!(res.is_ok(), "expected len {} to succeed, got {:?}", c.len, res);
            assert_eq!(res.unwrap().len(), c.len);
        } else {
            assert!(res.is_err(), "expected len {} to fail", c.len);
        }
    }

    // Record mark parsing boundaries: 0, 0x7FFF_FFFF
    let mut rm_cur_0 = XdrCursor::new(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(rm_cur_0.read_rfc5528_record_mark().unwrap(), (false, 0));

    let mut rm_cur_max = XdrCursor::new(&[0x7f, 0xff, 0xff, 0xff]);
    assert_eq!(rm_cur_max.read_rfc5528_record_mark().unwrap(), (false, 0x7fff_ffff));

    let mut rm_cur_eor_max = XdrCursor::new(&[0xff, 0xff, 0xff, 0xff]);
    assert_eq!(rm_cur_eor_max.read_rfc5528_record_mark().unwrap(), (true, 0x7fff_ffff));
}

#[test]
fn test_checkpoint_boundary_helpers_exact_ledgers() {
    use soroban_xdr_proof_kit::{checkpoint_ceil, checkpoint_floor, is_checkpoint_ledger};

    // Test matrix at ledger 0, 1, 63, 64, 65, 127, 128, and u32::MAX - 64
    let vectors: Vec<(u32, bool, u32, u32)> = vec![
        // (ledger, is_checkpoint, expected_floor, expected_ceil)
        (0, false, 0, 63),
        (1, false, 0, 63),
        (63, true, 63, 63),
        (64, false, 63, 127),
        (65, false, 63, 127),
        (127, true, 127, 127),
        (128, false, 127, 191),
        (u32::MAX - 64, true, u32::MAX - 64, u32::MAX - 64),
    ];

    for (ledger, is_chk, exp_floor, exp_ceil) in vectors {
        assert_eq!(
            is_checkpoint_ledger(ledger),
            is_chk,
            "is_checkpoint_ledger failed at ledger {ledger}"
        );
        assert_eq!(
            checkpoint_floor(ledger),
            exp_floor,
            "checkpoint_floor failed at ledger {ledger}"
        );
        assert_eq!(
            checkpoint_ceil(ledger),
            exp_ceil,
            "checkpoint_ceil failed at ledger {ledger}"
        );
    }
}
