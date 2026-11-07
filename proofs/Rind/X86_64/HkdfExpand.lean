module
public import Rind.X86_64.Kdf.Types
@[expose] public section
open Aeneas Aeneas.Std Result
set_option linter.dupNamespace false

/-!
# HKDF-Expand's loop, modelled by hand

`Prk::expand_into` loops over `info`, a slice of borrowed slices, which Aeneas
cannot translate ("Nested borrows are not supported yet"), so the translation
leaves it opaque and this file models it. `admin/prove` fails unless this quote
is still that Rust, so a change to it is a change to this model:

```rust
    fn expand_into(&self, info: &[&[u8]], out: &mut [u8]) {
        let _entry = Entry::new_secret();
        let mut block: Option<Digest> = None;
        for (counter, chunk) in (1..=255u8).zip(out.chunks_mut(self.0.algorithm().tag_len())) {
            let mut ctx = self.0.start();
            if let Some(block) = &block {
                ctx.update(block.as_ref());
            }
            for part in info {
                ctx.update(part);
            }
            ctx.update(&[counter]);
            let tag = ctx.finish();
            chunk.copy_from_slice(&tag.as_ref()[..chunk.len()]);
            block = Some(tag);
        }
    }

```

The model's recursion over `offset` is the loop over `out`'s chunks of the tag
length, each the bytes from `offset` to the next multiple or the end, which
`chunks_mut` panics on for a zero length, and `zip` ends after counter 255.
`info`'s loop is `foldlM`, and `&[counter]` the one-byte slice. It adds no
axiom.
-/

namespace rind.x86_64.kdf

/-- `&[counter]`. -/
def counterSlice (counter : Nat) : Slice Std.U8 :=
  .from [⟨BitVec.ofNat 8 counter⟩] (by simp; scalar_tac)

/-- `expand_into`'s loop from the chunk at `offset`, with counter `counter`,
after block `block`, over `n`-byte chunks. -/
def high.hkdf.Prk.expand_into_loop (self : high.hkdf.Prk) (info : Slice (Slice Std.U8))
    (n : Nat) (block : Option high.digest.Digest) (counter offset : Nat) (out : Slice Std.U8) :
    Result (Slice Std.U8) :=
  if _ : offset < out.length ∧ counter ≤ 255 ∧ 0 < n then do
    let ctx ← high.hmac.Key.start self
    let ctx ← match block with
      | none => ok ctx
      | some block => do
        let s ← high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref block
        high.hmac.Streaming.update ctx s
    let ctx ← info.val.foldlM high.hmac.Streaming.update ctx
    let ctx ← high.hmac.Streaming.update ctx (counterSlice counter)
    let tag ← high.hmac.Streaming.finish ctx
    let s ← high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref tag
    let len := min n (out.length - offset)
    if len ≤ s.length then
      high.hkdf.Prk.expand_into_loop self info n (some tag) (counter + 1) (offset + n)
        (out.setSlice! offset (s.val.take len))
    else fail .panic
  else ok out
termination_by out.length - offset
decreasing_by simp only [Slice.setSlice!_length]; omega

/-- `Prk::expand_into`. -/
def high.hkdf.Prk.expand_into (self : high.hkdf.Prk) (info : Slice (Slice Std.U8))
    (out : Slice Std.U8) : Result (Slice Std.U8) := do
  let _ ← low.entry.Entry.new_secret
  let a ← high.hmac.Key.algorithm self
  let n ← high.hmac.Algorithm.tag_len a
  if n.val = 0 then fail .panic
  else high.hkdf.Prk.expand_into_loop self info n.val none 1 0 out

end rind.x86_64.kdf
