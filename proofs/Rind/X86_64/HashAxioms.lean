import Rind.X86_64.Hmac
import Rind.X86_64.DigestApi
open rind.x86_64

/-!
The axioms the SHA-1, SHA-256, HMAC, and digest API theorems rest on, beyond
Lean's own: none. The block functions' contracts are `ShaBlocks`, a hypothesis
of each theorem. `Axioms` pins the theorems over every HMAC algorithm, which
rest on SHA-512's. A change here is a change to the trust base.
-/

/-- info: 'rind.x86_64.sha256_hash' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms sha256_hash

/-- info: 'rind.x86_64.sha1_hash' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms sha1_hash

/-- info: 'rind.x86_64.hmac_sha256_sign' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms hmac_sha256_sign

/-- info: 'rind.x86_64.hmac_sha1_sign' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms hmac_sha1_sign

/-- info: 'rind.x86_64.hmac_start_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms hmac_start_spec

/-- info: 'rind.x86_64.hmac_update_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms hmac_update_spec

/-- info: 'rind.x86_64.hmac_finish_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms hmac_finish_spec

/-- info: 'rind.x86_64.digest_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms digest_spec

/-- info: 'rind.x86_64.digest_ctx_new_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms digest_ctx_new_spec

/-- info: 'rind.x86_64.digest_ctx_update_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms digest_ctx_update_spec

/-- info: 'rind.x86_64.digest_ctx_finish_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms digest_ctx_finish_spec

