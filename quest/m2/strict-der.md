# [XS] Refuse trailing bytes after a key

## Goal

Every rind key loader (PKCS#8, SPKI, SEC1, PKCS#1, for ECDSA, RSA, Ed25519,
X25519, and ML-KEM where they parse DER) refuses bytes after the end of the
encoded key with `KeyRejected`, so rind-ring refuses them as ring does.

## Plan

Decided by the maintainer on 2026-10-31, after rind-ring found that ECDSA and
RSA `from_pkcs8` accept trailing bytes, as aws-lc-rs does and ring does not.
Trailing bytes are malformed input, and `AGENTS.md` says fail loud, so rind
is stricter than aws-lc-rs here; no real key file carries them.

- Find every loader that stops reading before the end of its input, not just
  PKCS#8, and refuse in the shared DER reader where possible so each format
  checks the same way.
- Record the difference from aws-lc-rs in MIGRATING.md, and drop it from
  rind-ring's differences if listed.
- Behavior change only; no signature changes.
