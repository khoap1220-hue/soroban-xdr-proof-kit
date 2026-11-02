use soroban_xdr_proof_kit::{
    bytes_to_hex, checkpoint_bounds_for_ledger, checkpoint_for_ledger,
    expected_archive_header_path, hex_to_bytes, sha256_digest, sha256_hex,
    verify_ancestry_chain, verify_raw_xdr_header_chain, LedgerHeaderLink, ProofError,
    RawLedgerHeaderXdr,
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

fn parse_json_value(raw: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":", key);
    if let Some(pos) = raw.find(&pattern) {
        let rest = raw[pos + pattern.len()..].trim_start();
        if rest.starts_with('"') {
            let s = &rest[1..];
            if let Some(end) = s.find('"') {
                return Some(s[..end].to_string());
            }
        } else {
            let mut end = 0;
            for c in rest.chars() {
                if c.is_ascii_digit() || c == '-' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > 0 {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn parse_chain_input(input: &str) -> Result<Vec<LedgerHeaderLink>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty chain input".into());
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1].trim();
        if inner.is_empty() {
            return Err("empty array".into());
        }

        // Check if array of JSON objects
        if inner.starts_with('{') {
            let mut links = Vec::new();
            let mut depth = 0;
            let mut start = None;
            for (i, c) in inner.char_indices() {
                if c == '{' {
                    if depth == 0 {
                        start = Some(i);
                    }
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = start {
                            let obj = &inner[s..=i];
                            let seq_str = parse_json_value(obj, "ledger_seq")
                                .ok_or_else(|| format!("missing ledger_seq in object: {obj}"))?;
                            let seq: u32 = seq_str
                                .parse()
                                .map_err(|e| format!("invalid ledger_seq {seq_str}: {e}"))?;
                            let prev = parse_json_value(obj, "previous_ledger_hash")
                                .or_else(|| parse_json_value(obj, "previous_ledger_hash_hex"))
                                .ok_or_else(|| "missing previous_ledger_hash".to_string())?;
                            let header = parse_json_value(obj, "header_hash")
                                .or_else(|| parse_json_value(obj, "header_hash_hex"))
                                .ok_or_else(|| "missing header_hash".to_string())?;
                            let tx_set = parse_json_value(obj, "tx_set_result_hash")
                                .or_else(|| parse_json_value(obj, "tx_set_result_hash_hex"))
                                .unwrap_or_else(|| "00".repeat(32));
                            links.push(LedgerHeaderLink {
                                ledger_seq: seq,
                                previous_ledger_hash_hex: prev,
                                header_hash_hex: header,
                                tx_set_result_hash_hex: tx_set,
                            });
                        }
                        start = None;
                    }
                }
            }
            if !links.is_empty() {
                return Ok(links);
            }
        }

        // Array of hex strings
        let items: Vec<&str> = inner.split(',').map(|s| s.trim().trim_matches('"').trim()).collect();
        let mut links = Vec::new();
        for item in items {
            let bytes = hex_to_bytes(item).map_err(|e| format!("hex decode: {e}"))?;
            let hdr = RawLedgerHeaderXdr::from_xdr_bytes(&bytes)
                .map_err(|e| format!("xdr decode: {e}"))?;
            let link = hdr.to_header_link().map_err(|e| format!("header link: {e}"))?;
            links.push(link);
        }
        return Ok(links);
    }

    // Comma-separated hex frames
    if trimmed.contains(',') {
        let items: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        let mut links = Vec::new();
        for item in items {
            let bytes = hex_to_bytes(item).map_err(|e| format!("hex decode: {e}"))?;
            let hdr = RawLedgerHeaderXdr::from_xdr_bytes(&bytes)
                .map_err(|e| format!("xdr decode: {e}"))?;
            let link = hdr.to_header_link().map_err(|e| format!("header link: {e}"))?;
            links.push(link);
        }
        return Ok(links);
    }

    // Single hex frame
    if let Ok(bytes) = hex_to_bytes(trimmed) {
        if let Ok(hdr) = RawLedgerHeaderXdr::from_xdr_bytes(&bytes) {
            if let Ok(link) = hdr.to_header_link() {
                return Ok(vec![link]);
            }
        }
    }

    Err(format!("unrecognized chain input: {trimmed}"))
}

fn execute_sample_chain() -> (Vec<LedgerHeaderLink>, u32, u32) {
    let target_seq = 1000;
    let certified_seq = 1004;
    let mut links = Vec::new();
    let mut prev = [0x01u8; 32];
    for seq in target_seq..=certified_seq {
        let hdr = build_sample_header(seq, prev);
        let link = hdr.to_header_link().expect("valid header link");
        let hash = hdr.compute_header_hash().expect("hash");
        prev = hash;
        links.push(link);
    }
    (links, target_seq, certified_seq)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  soroban-xdr-proof --json");
        eprintln!("  soroban-xdr-proof --verify-chain <input_json_or_hex>");
        eprintln!("  soroban-xdr-proof checkpoint <ledger_seq>");
        eprintln!("  soroban-xdr-proof sha256 <string>");
        eprintln!("  soroban-xdr-proof decode-xdr <hex_bytes>");
        eprintln!("  soroban-xdr-proof prove-xdr-range <target_seq> <certified_seq>");
        process::exit(2);
    }

    let is_json = args.iter().any(|a| a == "--json");
    let has_verify_chain = args.iter().any(|a| a == "--verify-chain");

    if has_verify_chain {
        let mut chain_arg = None;
        let mut idx = 1;
        while idx < args.len() {
            if args[idx] == "--verify-chain" {
                if idx + 1 < args.len() && !args[idx + 1].starts_with("--") {
                    chain_arg = Some(args[idx + 1].clone());
                    break;
                }
            }
            idx += 1;
        }

        let links = match chain_arg {
            Some(ref s) => match parse_chain_input(s) {
                Ok(l) => l,
                Err(e) => {
                    if is_json {
                        println!("{{\"ok\":false,\"error\":\"invalid arguments: {}\"}}", e);
                    } else {
                        eprintln!("Invalid chain arguments: {e}");
                    }
                    process::exit(2);
                }
            },
            None => {
                if is_json {
                    println!("{{\"ok\":false,\"error\":\"missing chain argument for --verify-chain\"}}");
                } else {
                    eprintln!("missing chain argument for --verify-chain");
                }
                process::exit(2);
            }
        };

        if links.is_empty() {
            if is_json {
                println!("{{\"ok\":false,\"error\":\"empty chain provided\"}}");
            } else {
                eprintln!("empty chain provided");
            }
            process::exit(2);
        }

        let min_seq = links.iter().map(|l| l.ledger_seq).min().unwrap_or(0);
        let max_seq = links.iter().map(|l| l.ledger_seq).max().unwrap_or(0);

        match verify_ancestry_chain(&links, min_seq, max_seq) {
            Ok(proof) => {
                let chk = checkpoint_for_ledger(max_seq);
                if is_json {
                    println!(
                        "{{\"ok\":true,\"checkpoint_seq\":{},\"ledger_count\":{},\"tip_hash\":\"{}\"}}",
                        chk, proof.chain_length, proof.certified_hash_hex
                    );
                } else {
                    println!(
                        "Chain valid: target_seq={} certified_seq={} checkpoint_seq={} tip_hash={}",
                        proof.target_seq, proof.certified_seq, chk, proof.certified_hash_hex
                    );
                }
                process::exit(0);
            }
            Err(e) => {
                let code = match e {
                    ProofError::HashMismatch { .. } | ProofError::SequenceDiscontinuity { .. } => 3,
                    _ => 2,
                };
                if is_json {
                    println!("{{\"ok\":false,\"error\":\"{}\"}}", e);
                } else {
                    eprintln!("Verification failed: {e}");
                }
                process::exit(code);
            }
        }
    }

    if is_json && args.len() == 2 {
        let (links, min_seq, max_seq) = execute_sample_chain();
        let proof = verify_ancestry_chain(&links, min_seq, max_seq).expect("sample chain valid");
        let chk = checkpoint_for_ledger(max_seq);
        println!(
            "{{\"ok\":true,\"checkpoint_seq\":{},\"ledger_count\":{},\"tip_hash\":\"{}\"}}",
            chk, proof.chain_length, proof.certified_hash_hex
        );
        process::exit(0);
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
                "{{\"ledger_seq\":{},\"checkpoint_seq\":{},\"range_start\":{},\"range_end\":{},\"archive_path\":\"{}\"}}",
                seq, chk, start_seq, end_seq, path
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
                    eprintln!("{{\"valid\":false,\"error\":\"{}\"}}", e);
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
                    eprintln!("{{\"valid\":false,\"error\":\"{}\"}}", e);
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
                    eprintln!("{{\"verified\":false,\"error\":\"{}\"}}", e);
                    process::exit(2);
                }
            }
        }
        other => {
            eprintln!("Unknown command: {other}");
            process::exit(2);
        }
    }
}
