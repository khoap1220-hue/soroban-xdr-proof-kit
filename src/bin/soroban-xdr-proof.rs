use soroban_xdr_proof_kit::{
    bytes_to_hex, checkpoint_bounds_for_ledger, checkpoint_for_ledger,
    expected_archive_header_path, hex_to_bytes, sha256_digest, sha256_hex,
    verify_raw_xdr_header_chain, RawLedgerHeaderXdr,
};
use std::env;
use std::process;

fn build_sample_header(seq: u32, prev_hash: [u8; 32]) -> RawLedgerHeaderXdr {
    RawLedgerHeaderXdr {
        ledger_version: 21,
        previous_ledger_hash: prev_hash,
        tx_set_hash: [0x11; 32],
        close_time: 1_730_000_000 + (seq as u64) * 5,
        upgrades_opaque: vec![0xaa, 0xbb],
        scp_value_ext: 0,
        tx_set_result_hash: [0x22; 32],
        bucket_list_hash: [0x33; 32],
        ledger_seq: seq,
        total_coins: 100_000_000_000_000_000,
        fee_pool: 5_000_000,
        inflation_seq: 0,
        id_pool: 9999,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 1000,
        skip_list: [[0u8; 32]; 4],
        ext: 0,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  soroban-xdr-proof checkpoint <ledger_seq>");
        eprintln!("  soroban-xdr-proof sha256 <string>");
        eprintln!("  soroban-xdr-proof decode-xdr <hex_bytes>");
        eprintln!("  soroban-xdr-proof prove-xdr-range <target_seq> <certified_seq>");
        process::exit(1);
    }

    match args[1].as_str() {
        "checkpoint" => {
            let seq: u32 = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(64_791_250);
            let chk = checkpoint_for_ledger(seq);
            let (start_seq, end_seq) = checkpoint_bounds_for_ledger(seq);
            let path = expected_archive_header_path(seq);
            println!(
                "{{\"ledger_seq\":{seq},\"checkpoint_seq\":{chk},\"range_start\":{start_seq},\"range_end\":{end_seq},\"archive_path\":\"{path}\"}}"
            );
        }
        "sha256" => {
            let payload = args.get(2).map(|s| s.as_bytes()).unwrap_or(b"");
            println!("{}", sha256_hex(payload));
        }
        "decode-xdr" => {
            let hex_arg = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let raw = match hex_to_bytes(hex_arg) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{{\"valid\":false,\"error\":\"{e}\"}}");
                    process::exit(2);
                }
            };
            match RawLedgerHeaderXdr::from_xdr_bytes(&raw) {
                Ok(hdr) => {
                    let wire_hash = bytes_to_hex(&sha256_digest(&raw));
                    let prev_hex = bytes_to_hex(&hdr.previous_ledger_hash);
                    let archive_path = expected_archive_header_path(hdr.ledger_seq);
                    println!(
                        "{{\"valid\":true,\"ledger_seq\":{},\"ledger_version\":{},\"scp_value_ext\":{},\"ext\":{},\"previous_ledger_hash\":\"{}\",\"header_hash\":\"{}\",\"archive_path\":\"{}\"}}",
                        hdr.ledger_seq,
                        hdr.ledger_version,
                        hdr.scp_value_ext,
                        hdr.ext,
                        prev_hex,
                        wire_hash,
                        archive_path
                    );
                }
                Err(e) => {
                    eprintln!("{{\"valid\":false,\"error\":\"{e}\"}}");
                    process::exit(2);
                }
            }
        }
        "prove-xdr-range" => {
            let target_seq: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
            let certified_seq: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1004);
            let mut raw_frames = Vec::new();
            let mut prev = [0x01u8; 32];
            for seq in target_seq..=certified_seq {
                let hdr = build_sample_header(seq, prev);
                prev = hdr.compute_header_hash().expect("valid XDR");
                raw_frames.push(hdr.to_xdr_bytes().expect("serialize XDR"));
            }
            match verify_raw_xdr_header_chain(&raw_frames, target_seq, certified_seq) {
                Ok(proof) => {
                    println!(
                        "{{\"verified\":true,\"target_seq\":{},\"certified_seq\":{},\"chain_length\":{},\"target_hash\":\"{}\",\"certified_hash\":\"{}\"}}",
                        proof.target_seq,
                        proof.certified_seq,
                        proof.chain_length,
                        proof.target_hash_hex,
                        proof.certified_hash_hex
                    );
                }
                Err(e) => {
                    eprintln!("{{\"verified\":false,\"error\":\"{e}\"}}");
                    process::exit(2);
                }
            }
        }
        other => {
            eprintln!("Unknown command: {other}");
            process::exit(1);
        }
    }
}
