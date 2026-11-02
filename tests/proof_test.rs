use soroban_xdr_proof_kit::{
    checkpoint_for_ledger, expected_archive_header_path, verify_ancestry_chain, LedgerHeaderLink,
    ProofError,
};

fn sample_hash(byte_char: char) -> String {
    std::iter::repeat(byte_char).take(64).collect()
}

#[test]
fn test_checkpoint_and_archive_path_formatting() {
    assert_eq!(checkpoint_for_ledger(64791250), 64791295);
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
    assert_eq!(proof.target_hash_hex, sample_hash('b'));
    assert_eq!(proof.certified_hash_hex, sample_hash('d'));
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
fn test_detects_tampered_previous_ledger_hash() {
    let h10 = LedgerHeaderLink {
        ledger_seq: 10,
        previous_ledger_hash_hex: sample_hash('1'),
        header_hash_hex: sample_hash('2'),
        tx_set_result_hash_hex: sample_hash('9'),
    };
    let h11_tampered = LedgerHeaderLink {
        ledger_seq: 11,
        previous_ledger_hash_hex: sample_hash('f'),
        header_hash_hex: sample_hash('3'),
        tx_set_result_hash_hex: sample_hash('8'),
    };

    let err = verify_ancestry_chain(&[h10, h11_tampered], 10, 11).unwrap_err();
    assert!(matches!(err, ProofError::HashMismatch { ledger_seq: 11, .. }));
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

    let err = verify_ancestry_chain(&[h100, h102], 100, 102).unwrap_err();
    assert_eq!(
        err,
        ProofError::MissingHeader {
            ledger_seq: 101,
            expected_archive_path: "ledger/00/00/00/ledger-0000007f.xdr.gz".to_string()
        }
    );
}
