# Roadmap — `soroban-xdr-proof-kit`

- [x] Pure-Rust FIPS 180-4 SHA-256 engine (`sha256_digest`) with zero external dependencies.
- [x] RFC 4506 binary `LedgerHeader` XDR parser and serializer (`STELLAR_VALUE_SIGNED` & `LedgerHeaderExtensionV1`).
- [x] 64-bit overflow-safe Stellar History Archive checkpoint sequence math (`checkpoint_bounds_for_seq`).
- [x] Binary SHA-256 Merkle inclusion proof verifier (`verify_merkle_branch`) for Soroban state keys.
- [ ] Soroban `LedgerCloseMeta` v1/v2 full envelope stream framing reader.
