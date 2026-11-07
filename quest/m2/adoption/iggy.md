# [S] Apache Iggy encrypts streams with rind

## Goal

A PR to [Apache Iggy](https://github.com/apache/iggy), with numbers from its
own `stream_encryption` benchmark, moves its AES-256-GCM message encryption
from RustCrypto onto rind.

## Plan

Decided with the maintainer on 2026-11-04, in a planning interview. Its
AES-GCM-SIV option stays on RustCrypto (rind has none). Apache projects take
contributions through their own process; follow it. Posting is the
maintainer's call.

The patch is ready and tested: `iggy_common`'s client-side
`Aes256GcmEncryptor` and the server's stream-key envelope seal with rind, and
`aes-gcm` drops to a dev-dependency. It lives at
[`patches/1-rind.patch`](https://github.com/moq-dev/rind/blob/scratch/iggy-bench/patches/1-rind.patch)
on the `scratch/iggy-bench` branch, with the bench probe that measured it;
[moq-dev/rind#474](https://github.com/moq-dev/rind/pull/474) holds the numbers
and the facts for the issue.

- Iggy wants an approved issue, assigned to the person who opens the PR,
  before any code. That person writes the rationale in their own words and
  must be able to defend every line. Maintainers can close agent-driven PRs
  without review. So the maintainer opens the issue and, once assigned, the PR.
- Iggy's newer per-stream server-side keys encrypt with AES-256-GCM-SIV; plain
  AES-256-GCM is the SDK's client-side encryption and the key envelope.
- Iggy ships x86_64 and aarch64 only, which rind covers.

## Waiting

- Maintainer: open the apache/iggy issue in your own words from the facts in
  [moq-dev/rind#474](https://github.com/moq-dev/rind/pull/474) (recommended),
  or drop the quest. An agent cannot: Iggy closes agent-driven PRs and wants
  the author to answer review themselves. Check with
  `gh issue list -R apache/iggy --author @me --search rind`; once assigned,
  open the PR from the patch.
