# [XS] aws-lc-rs extras on demand

## Goal

Each aws-lc-rs algorithm beyond ring's set gets a quest when a consumer asks for it: ML-KEM-512 and ML-KEM-1024, RSA-OAEP encryption, AES-192, AES's CBC, ECB, CFB, and OFB modes, DES, AES key wrap, CMAC, KBKDF and SSKDF, the TLS 1.2 PRF, AES-GCM-SIV, SHA-224, SHA-3, ECDSA on secp256k1 or over other curve and hash pairings, and ML-DSA. `MIGRATING.md` maps each to this quest. This quest only waits; check new issues and MoQ's needs when triaging, plan the asked-for algorithm with `/quest-plan`, and delete this quest once the list is empty or abandoned.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.
