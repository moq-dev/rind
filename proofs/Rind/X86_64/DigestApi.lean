import Rind.X86_64.Hmac
import Rind.X86_64.DigestDispatch
open Aeneas Aeneas.Std Result rind.spec

/-!
# The digest API, `high::digest`, through the modelled dispatch

`digest` and `Context` compute FIPS 180-4's SHA-1 and SHA-256, through the
dispatch `Rind.X86_64.DigestDispatch` models, down to each hash's `HashSpec`;
`Rind.X86_64.Sha512` proves the SHA-512 family's. `CtxOf` says what a
`Context` has been given.
`admin/prove` writes the aarch64 proof from this file by renaming the target.
-/

namespace rind.x86_64

/-! ## Over any hash meeting `HashSpec` -/

section
variable {Self C S : Type} {inst : high.hash.Hash Self C S} {H : List Byte → List Byte}
  {B L max : Nat} {Abs : List U8 → S → Prop} {CAbs : List U8 → C → Prop}

theorem hashing_update_spec (hs : HashSpec inst H B L max Abs CAbs)
    (V : high.digest.Variant C) (hV : V.hashHashContextInst = inst.HashContextInst)
    (p : List U8) (h : high.digest.Hashing C) (hc : CAbs p h.context) (data : Slice U8)
    (hl : p.length + data.length ≤ max) :
    high.digest.Hashing.update V h data ⦃ h' => CAbs (p ++ data.val) h'.context ⦄ := by
  unfold high.digest.Hashing.update
  rw [hV]
  step with hs.update p _ data hc hl as ⟨c, hc'⟩
  exact hc'

theorem hashing_finish_spec (hs : HashSpec inst H B L max Abs CAbs)
    (V : high.digest.Variant C) (hV : V.hashHashContextInst = inst.HashContextInst)
    (hfr : V.finish_reset = high.digest.Variant.finish_reset.default V)
    (hnew : V.NEW ⦃ c => CAbs [] c ⦄) (p : List U8) (h : high.digest.Hashing C)
    (hc : CAbs p h.context) (hl : p.length ≤ max) :
    high.digest.Hashing.finish V h ⦃ r =>
      outLen r.1.algorithm = L ∧ digestBytes r.1 = H (bv p) ∧ CAbs [] r.2.context ⦄ := by
  unfold high.digest.Hashing.finish
  rw [hfr]
  unfold high.digest.Variant.finish_reset.default
  rw [hV]
  step with hs.finish p _ hc hl as ⟨d, hd1, hd2⟩
  step with hnew as ⟨c, hc0⟩
  exact ⟨hd1, hd2, hc0⟩

end

/-! ## Each variant's fresh context -/

theorem sha1_variant_new_spec :
    high.hash.Sha1Context.Insts.RindHighDigestVariant.NEW ⦃ c => Sha1Ctx [] c ⦄ := by
  unfold high.hash.Sha1Context.Insts.RindHighDigestVariant.NEW mid.sha1.Sha1Context.new
  step with sha1_new_spec as ⟨s, hs⟩
  step with sha1_resume_spec [] s hs as ⟨c, hc⟩
  exact hc

theorem sha256_variant_new_spec :
    high.hash.Sha256Context.Insts.RindHighDigestVariant.NEW ⦃ c => Sha256Ctx [] c ⦄ := by
  unfold high.hash.Sha256Context.Insts.RindHighDigestVariant.NEW mid.sha2.Sha256Context.new
  step with sha256_new_spec as ⟨s, hs⟩
  step with sha256_resume_spec [] s hs as ⟨c, hc⟩
  exact hc

/-! ## The API -/

/-- The hash each algorithm proven here runs, over spec bytes. -/
def digestHash : high.digest.Algorithm → List Byte → List Byte
  | .SHA1 => sha1.hash
  | _ => sha256.hash

/-- What the digest API under `a` needs: `a` is SHA-1 or SHA-256, the entry
guard passes, and the block functions meet their contracts. -/
def RunsDigest (a : high.digest.Algorithm) : Prop :=
  (a = .SHA1 ∨ a = .SHA256) ∧ (∃ e, low.entry.Entry.new_secret = ok e) ∧ ShaBlocks

/-- `c` is a `Context` of `a` that has been given `p`. -/
def CtxOf (a : high.digest.Algorithm) (p : List U8) : high.digest.State → Prop
  | .Sha1 h => a = .SHA1 ∧ Sha1Ctx p h.context
  | .Sha256 h => a = .SHA256 ∧ Sha256Ctx p h.context
  | _ => False

/-- `digest::digest`. -/
theorem digest_spec (a : high.digest.Algorithm) (hr : RunsDigest a) (data : Slice U8)
    (hl : data.length ≤ maxInput) :
    high.digest.digest a data ⦃ d =>
      outLen d.algorithm = outLen a ∧ digestBytes d = digestHash a (bv data.val) ⦄ := by
  obtain ⟨ha, ⟨e, he⟩, hb⟩ := hr
  unfold high.digest.digest
  rw [he, bind_ok]
  rcases ha with rfl | rfl
  · simp only [high.digest.Algorithm.hash]
    rw [← (sha1_hashSpec hb).hash_default]
    exact (sha1_hashSpec hb).hash_spec data hl
  · simp only [high.digest.Algorithm.hash]
    rw [← (sha256_hashSpec hb).hash_default]
    exact (sha256_hashSpec hb).hash_spec data hl

/-- `Context::new`. -/
theorem digest_ctx_new_spec (a : high.digest.Algorithm) (hr : RunsDigest a) :
    high.digest.Context.new a ⦃ c => CtxOf a [] c ⦄ := by
  unfold high.digest.Context.new
  rcases hr.1 with rfl | rfl
  all_goals simp only [high.digest.Algorithm.start, high.digest.Hashing.start,
    high.hash.Sha1Context.Insts.RindHighDigestVariant.state,
    high.hash.Sha256Context.Insts.RindHighDigestVariant.state]
  · step with sha1_variant_new_spec as ⟨c, hc⟩
    exact ⟨rfl, hc⟩
  · step with sha256_variant_new_spec as ⟨c, hc⟩
    exact ⟨rfl, hc⟩

/-- `Context::update`. -/
theorem digest_ctx_update_spec (a : high.digest.Algorithm) (hr : RunsDigest a) (p : List U8)
    (c : high.digest.Context) (hc : CtxOf a p c) (data : Slice U8)
    (hl : p.length + data.length ≤ maxInput) :
    high.digest.Context.update c data ⦃ c' => CtxOf a (p ++ data.val) c' ⦄ := by
  have hb := hr.2.2
  unfold high.digest.Context.update high.digest.State.update
  cases c <;> simp only [CtxOf] at hc
  all_goals obtain ⟨rfl, hc⟩ := hc
  · step with hashing_update_spec (sha1_hashSpec hb)
      high.hash.Sha1Context.Insts.RindHighDigestVariant rfl p _ hc data hl as ⟨h', hh⟩
    exact ⟨rfl, hh⟩
  · step with hashing_update_spec (sha256_hashSpec hb)
      high.hash.Sha256Context.Insts.RindHighDigestVariant rfl p _ hc data hl as ⟨h', hh⟩
    exact ⟨rfl, hh⟩

/-- `Context::finish`, which leaves the context fresh. -/
theorem digest_ctx_finish_spec (a : high.digest.Algorithm) (hr : RunsDigest a) (p : List U8)
    (c : high.digest.Context) (hc : CtxOf a p c) (hl : p.length ≤ maxInput) :
    high.digest.Context.finish c ⦃ r =>
      outLen r.1.algorithm = outLen a ∧ digestBytes r.1 = digestHash a (bv p) ∧
        CtxOf a [] r.2 ⦄ := by
  obtain ⟨-, ⟨e, he⟩, hb⟩ := hr
  unfold high.digest.Context.finish high.digest.State.finish
  rw [he, bind_ok]
  cases c <;> simp only [CtxOf] at hc
  all_goals obtain ⟨rfl, hc⟩ := hc
  · step with hashing_finish_spec (sha1_hashSpec hb)
      high.hash.Sha1Context.Insts.RindHighDigestVariant rfl rfl sha1_variant_new_spec p _ hc hl
      as ⟨r, hh, h1, h2, h3⟩
    exact ⟨h1, h2, rfl, h3⟩
  · step with hashing_finish_spec (sha256_hashSpec hb)
      high.hash.Sha256Context.Insts.RindHighDigestVariant rfl rfl sha256_variant_new_spec p _ hc
      hl as ⟨r, hh, h1, h2, h3⟩
    exact ⟨h1, h2, rfl, h3⟩

end rind.x86_64
