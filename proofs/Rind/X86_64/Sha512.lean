import Rind.X86_64.AwsLc
import Rind.X86_64.DigestDispatch
import Rind.X86_64.Sha
import Rind.Bytes
open Aeneas Aeneas.Std Result rind.spec

/-!
# The SHA-512 family, proven from rind's digest API to aws-lc's contract

`sha512_family_digest` and `sha512_family_context` state what the digest API
returns for SHA-384, SHA-512, and SHA-512/256, in terms of `Rind.Sha2`'s spec,
through the dispatch `Rind.X86_64.DigestDispatch` models. Below them, a
context's state holds the chaining value after the whole blocks it has
compressed and its buffer the rest (`Hashed`), and finishing pads that rest
and compresses it as FIPS 180-4 does. `admin/prove` writes the aarch64 proof
from this file by renaming the target.
-/

namespace rind.x86_64

/-! ## Padding, `low::generic::blockwise` -/

/-- The list `pad` writes. -/
theorem sha512_pad_list (r l : List U8) (P : Nat) (hl : l.length = 16) (hP : r.length + 17 ≤ P) :
    (((List.replicate P 0#u8).setSlice! 0 r).set r.length 0x80#u8).setSlice! (P - 16) l =
      r ++ 0x80#u8 :: List.replicate (P - r.length - 17) 0#u8 ++ l := by
  have hA : (List.replicate P 0#u8).setSlice! 0 r = r ++ List.replicate (P - r.length) 0#u8 := by
    simp [List.setSlice!, show min r.length P = r.length by omega, List.drop_replicate]
  have hB : (r ++ List.replicate (P - r.length) 0#u8).set r.length 0x80#u8 =
      (r ++ 0x80#u8 :: List.replicate (P - r.length - 17) 0#u8) ++ List.replicate 16 0#u8 := by
    rw [List.set_append_right _ _ (by omega)]
    simp only [Nat.sub_self]
    rw [show P - r.length = (P - r.length - 17 + 16) + 1 by omega, List.replicate_succ]
    simp [List.replicate_add]
  rw [hA, hB]
  generalize hX : r ++ 0x80#u8 :: List.replicate (P - r.length - 17) 0#u8 = X
  have hlen : X.length = P - 16 := by rw [← hX]; simp; omega
  simp only [List.setSlice!, List.length_append, List.length_replicate, hlen, hl,
    show min 16 (P - 16 + 16 - (P - 16)) = 16 by omega, List.take_of_length_le (le_of_eq hl)]
  rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega),
    List.drop_eq_nil_of_le (by simp; omega)]
  simp

theorem zero_blocks_flat :
    (Std.Array.repeat 2#usize (Std.Array.repeat 128#usize 0#u8)).val.flatMap (·.val) =
      List.replicate 256 0#u8 := by
  simp [Std.Array.repeat]

/-- `pad` writes the message's tail, the 0x80 byte, zeros, and the length. -/
@[step]
theorem sha512_pad_spec (rest : Slice U8) (length : Std.Array U8 16#usize)
    (hr : rest.length < 256) (hr' : 128 ≤ rest.length → rest.length % 128 ≤ 111) :
    low.generic.blockwise.pad (N := 128#usize) rest length
      (Std.Array.repeat 2#usize (Std.Array.repeat 128#usize 0#u8)) ⦃ s _ =>
      s.val = rest.val ++ 0x80#u8 :: List.replicate ((239 - rest.length % 128) % 128) 0#u8 ++
        length.val ⦄ := by
  unfold low.generic.blockwise.pad
  step*
  have hflat := zero_blocks_flat
  have hlen : rest.len.val = rest.length := by simp
  split_ifs with hfit <;> step*
  all_goals
    have hs1 : s1.val = List.replicate 256 0#u8 := by rw [s1_post, s_post, hflat]
    have hlast1 : last1.val = List.replicate padded.val 0#u8 := by
      have : padded.val ≤ 256 := by scalar_tac
      rw [last1_post, hs1, List.slice, List.drop_zero, Nat.sub_zero, List.take_replicate,
        min_eq_left this]
    have hb1 : (index_mut_back1 s3).val = (List.replicate padded.val 0#u8).setSlice! 0 rest.val := by
      rw [s2_post2, hlast1, s3_post]
    have hlast3 : last3.val = ((List.replicate padded.val 0#u8).setSlice! 0 rest.val).set rest.length 0x80#u8 := by
      rw [last3_post, Slice.set_val_eq, hb1]; simp
    have hl3 : last3.length = padded.val := by simp [Slice.length, hlast3, List.length_setSlice!]
    first
    | simp [s4_post1, hl3, i6_post, s5_post, Slice.length]; omega
    | have hP : rest.length + 17 ≤ padded.val := by scalar_tac
      have hz : padded.val - rest.length - 17 = (239 - rest.length % 128) % 128 := by scalar_tac
      rw [s4_post2, hlast3, s6_post, s5_post, Array.val_to_slice, i6_post,
        sha512_pad_list _ _ _ (by simp) hP, hz]

/-- `split_tail` leaves whole blocks, then a tail that `pad` fits in two blocks. -/
@[step]
theorem sha512_split_tail_spec (message : Slice U8) :
    low.generic.blockwise.split_tail 128#usize 16#usize message ⦃ blocks rest =>
      blocks.val ++ rest.val = message.val ∧ blocks.length % 128 = 0 ∧
      rest.length % 128 = message.length % 128 ∧ rest.length < 256 ∧
      (128 ≤ rest.length → rest.length % 128 ≤ 111) ⦄ := by
  unfold low.generic.blockwise.split_tail
  step*
  split_ifs <;> step* <;> simp only [Slice.length] at * <;>
    rw [blocks_post2, blocks_post3, List.take_append_drop] <;> refine ⟨rfl, ?_⟩ <;> scalar_tac

/-! ## Finishing, `mid::sha2::Sha512State::finish_with` -/

theorem finish_with_loop_spec
    (it : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter Std.U64))
    (r : Std.Array U8 64#usize) (V : List U64) (hVl : V.length = 8)
    (hV : it.iter.slice.val = V) (hi : it.iter.i = it.count.val) (hk : it.count.val ≤ 8)
    (hr : r.val.take (8 * it.count.val) = (V.take it.count.val).flatMap beBytes) :
    mid.sha2.Sha512State.finish_with_loop it r ⦃ r' => r'.val = V.flatMap beBytes ⦄ := by
  unfold mid.sha2.Sha512State.finish_with_loop
  apply loop.spec_decr_nat (fun x => 8 - x.1.count.val)
    (fun x => x.1.iter.slice.val = V ∧ x.1.iter.i = x.1.count.val ∧ x.1.count.val ≤ 8 ∧
      x.2.val.take (8 * x.1.count.val) = (V.take x.1.count.val).flatMap beBytes)
  · rintro ⟨it, r⟩ ⟨hV, hi, hk, hr⟩
    simp only at hV hi hk hr ⊢
    unfold mid.sha2.Sha512State.finish_with_loop.body
    simp only [core.iter.adapters.enumerate.IteratorEnumerate.next,
      core.slice.iter.IteratorSliceIter.next]
    have hsl : it.iter.slice.len.val = 8 := by simp [Slice.len, hV, hVl]
    split
    · rename_i hlt
      have hk8 : it.count.val < 8 := by omega
      step*
      · rw [s_post1, s1_post]
        simp [i3_post, i2_post, i1_post, Slice.length]
        omega
      · have ha8 : (a.val).length = 8 := a.property
        have hw : it.iter.slice[it.iter.i] = V[it.count.val] := by
          subst hV
          show it.iter.slice.val[it.iter.i]'(by simp [Slice.len] at hlt; omega) = _
          simp only [hi]
        refine ⟨hV, by omega, by omega, ?_, by omega⟩
        rw [s_post2, s2_post, s1_post]
        have hr64 : (r.val).length = 64 := r.property
        have := take_setSlice! r.val a.val (i1.val) (by rw [ha8, i1_post]; omega)
        simp only [Array.val_to_slice, ha8] at this ⊢
        rw [show 8 * x.val = i1.val + 8 by rw [x_post, i1_post]; ring, this, i1_post,
          show it.count.val * 8 = 8 * it.count.val by ring, hr, x_post, List.take_add_one,
          List.flatMap_append, List.getElem?_eq_getElem (by omega)]
        simp [a_post, hw, beBytes]
    · rename_i hlt
      have hk8 : it.count.val = 8 := by omega
      have hr64 : (r.val).length = 64 := r.property
      rw [hk8, List.take_of_length_le (by omega), List.take_of_length_le (by omega)] at hr
      simpa [WP.spec_ok] using hr
  · exact ⟨hV, hi, hk, hr⟩

@[step]
theorem from_u128_u64_spec (x : U64) :
    lift (core.convert.num.FromU128U64.from x) ⦃ y => y.val = x.val ⦄ := by
  simp [lift, core.convert.num.FromU128U64.from_val_eq]

@[step]
theorem compress_spec (h : RunsSha512) (state : Std.Array U64 8#usize) (blocks : Slice U8)
    (hm : blocks.length % 128 = 0) :
    mid.sha2.Sha512State.compress state blocks ⦃ r => r.val = compress state.val blocks.val ⦄ := by
  unfold mid.sha2.Sha512State.compress
  step*

/-- `finish_with` hashes the message after the state's blocks, padded. -/
@[step]
theorem finish_with_spec (h : RunsSha512) (self : mid.sha2.Sha512State) (message : Slice U8) :
    mid.sha2.Sha512State.finish_with self message ⦃ r =>
      r.val = (compress self.h.val (padAfter (128 * self.nblocks.val) message.val)).flatMap beBytes ⦄ := by
  unfold mid.sha2.Sha512State.finish_with
  have hB : (UScalar.cast .U128 mid.sha2.Sha512State.finish_with.BLOCK_SZ).val = 128 := by
    simp [mid.sha2.Sha512State.finish_with.BLOCK_SZ, mid.sha2.Sha512Context.BLOCK_SZ, UScalar.cast_val_eq]
  have hL : (UScalar.cast .U128 message.len).val = message.length := by
    have := slice_length_lt message
    simp [UScalar.cast_val_eq, Slice.length] at this ⊢; omega
  have hn : self.nblocks.val < 2 ^ 64 := self.nblocks.hBounds
  have hm : message.length < 2 ^ 64 := slice_length_lt message
  step*
  have hbits : bits.val = 8 * (128 * self.nblocks.val + message.length) := by
    rw [bits_post, i5_post, i2_post, i_post, i1_post, hB, i4_post, hL]; ring
  have hh : (if b = true then ok self.h else mid.sha2.Sha512State.compress self.h blocks) ⦃ h' =>
      h'.val = compress self.h.val blocks.val ⦄ := by
    split
    · have : blocks.val = [] := List.eq_nil_of_length_eq_zero (by simp_all [Slice.length])
      simp [this]
    · step*
  step with hh as ⟨h', hh'⟩
  step*
  · have : (a1.val).length = 16 := by simp
    simp only [Slice.length, s_post, List.length_append, List.length_cons, List.length_replicate] at this ⊢
    omega
  · simp only [core.slice.Slice.iter]
    step*
    have hl : (h1.val).length = 8 := h1.property
    apply WP.spec_mono (finish_with_loop_spec iter _ h1.val hl ?_ ?_ ?_ ?_)
    · intro r hr
      rw [hr, h1_post, hh', ← compress_append _ _ _ blocks_post1]
      congr 2
      have hbv : bits.bv = BitVec.ofNat 128 (8 * (128 * self.nblocks.val + message.length)) := by
        apply BitVec.eq_of_toNat_eq
        rw [BitVec.toNat_ofNat, ← hbits]
        exact (Nat.mod_eq_of_lt bits.bv.isLt).symm
      have hml : (blocks.val ++ rest.val).length = message.val.length := by rw [blocks_post]
      rw [s_post, a1_post, hbv, padAfter, ← blocks_post2, ← blocks_post]
      simp only [List.append_assoc, Slice.length, List.cons_append, hml]
    all_goals simp [iter_post, iter_post1, s1_post, Array.val_to_slice]

/-! ## Updating, `mid::sha2::Sha512Context::update` -/

@[step]
theorem saturating_add_spec (x y : U64) (h : x.val + y.val < 2 ^ 64) :
    lift (core.num.U64.saturating_add x y) ⦃ z => z.val = x.val + y.val ⦄ := by
  simp only [lift, WP.spec_ok, core.num.U64.saturating_add, UScalar.saturating_add]
  show (BitVec.ofNat _ _).toNat = _
  rw [BitVec.toNat_ofNat, min_eq_right (by simp [U64.max_eq]; omega)]
  simp; omega

/-- `update_blocks` compresses whole blocks and counts them. -/
@[step]
theorem update_blocks_spec (h : RunsSha512) (st : mid.sha2.Sha512State) (blocks : Slice U8)
    (hm : blocks.length % 128 = 0) (hn : st.nblocks.val + blocks.length / 128 < 2 ^ 64) :
    mid.sha2.Sha512State.Insts.RindLowGenericBlockwiseUpdateBlocks.update_blocks st blocks ⦃ st' =>
      st'.h.val = compress st.h.val blocks.val ∧
        st'.nblocks.val = st.nblocks.val + blocks.length / 128 ⦄ := by
  unfold mid.sha2.Sha512State.Insts.RindLowGenericBlockwiseUpdateBlocks.update_blocks
  have hB : mid.sha2.Sha512Context.BLOCK_SZ.val = 128 := by simp [mid.sha2.Sha512Context.BLOCK_SZ]
  step*
  rename_i hb
  have h0 : blocks.length = 0 := by simpa [hb] using b1_post
  simp [compress_short _ _ (by omega : blocks.length < 128), h0]

/-- The state after an optional `update_blocks`, skipped for no blocks. -/
theorem update_blocks_if_spec (h : RunsSha512) (b : Bool) (st : mid.sha2.Sha512State)
    (blocks : Slice U8) (hb : (b = true) = (blocks.length = 0)) (hm : blocks.length % 128 = 0)
    (hn : st.nblocks.val + blocks.length / 128 < 2 ^ 64) :
    (if b = true then ok st
      else mid.sha2.Sha512State.Insts.RindLowGenericBlockwiseUpdateBlocks.update_blocks st blocks)
      ⦃ st' => st'.h.val = compress st.h.val blocks.val ∧
        st'.nblocks.val = st.nblocks.val + blocks.length / 128 ⦄ := by
  split
  · rename_i hb'
    have h0 : blocks.length = 0 := by simpa [hb'] using hb
    simp [compress_short _ _ (by omega : blocks.length < 128), h0]
  · step*

/-- `omega` once every slice length reads as its list's. -/
macro "len_omega" : tactic => `(tactic| (try simp only [Slice.length, Slice.len_val] at *) <;> omega)

theorem setSlice!_fill {α : Type _} (buf hd : List α) (u : Nat) (h : u + hd.length = buf.length) :
    buf.setSlice! u hd = buf.take u ++ hd := by
  simp only [List.setSlice!, show min hd.length (buf.length - u) = hd.length by omega,
    List.take_of_length_le (le_refl _), List.drop_eq_nil_of_le (show buf.length ≤ u + hd.length by omega),
    List.append_nil]

theorem take_setSlice!_zero {α : Type _} (buf r : List α) (h : r.length ≤ buf.length) :
    (buf.setSlice! 0 r).take r.length = r := by
  have := take_setSlice! buf r 0 (by omega)
  simpa using this

/-- `complete_blocks` compresses the buffered bytes and `bytes` up to their
last 1 to 128 bytes, which it buffers. -/
theorem sha512_complete_blocks_spec (h : RunsSha512) (bw : low.generic.blockwise.Blockwise 128#usize)
    (bytes : Slice U8) (st : mid.sha2.Sha512State) (hu : bw.used.val ≤ 128)
    (hlong : 128 < bw.used.val + bytes.length)
    (hn : st.nblocks.val + (bw.used.val + bytes.length) / 128 < 2 ^ 64) :
    low.generic.blockwise.Blockwise.complete_blocks
      mid.sha2.Sha512State.Insts.RindLowGenericBlockwiseUpdateBlocks bw bytes st ⦃ bw' st' =>
      let all := bw.buffer.val.take bw.used.val ++ bytes.val
      let k := (all.length - 1) / 128 * 128
      st'.h.val = compress st.h.val (all.take k) ∧ st'.nblocks.val = st.nblocks.val + k / 128 ∧
        bw'.used.val = all.length - k ∧ bw'.buffer.val.take bw'.used.val = all.drop k ⦄ := by
  unfold low.generic.blockwise.Blockwise.complete_blocks
  have hbl : (bw.buffer.val).length = 128 := bw.buffer.property
  have hlen : (bw.buffer.val.take bw.used.val ++ bytes.val).length = bw.used.val + bytes.length := by
    simp [Slice.length]; omega
  split
  · rename_i hpos
    step as ⟨i, hi, hi'⟩
    step as ⟨hr, hhl, hrl, hhv, hrv⟩
    obtain ⟨head, rest1⟩ := hr
    simp only at *
    step as ⟨sb, hsv, hsl, hback⟩
    obtain ⟨s, back⟩ := sb
    simp only at *
    step as ⟨s1, hs1⟩
    step as ⟨s2, hs2⟩
    have hhead : head.val.length = 128 - bw.used.val := by
      simp only [Slice.length] at hhl; omega
    have hfull : (back s1).val = bw.buffer.val.take bw.used.val ++ head.val := by
      rw [hback, hs1, setSlice!_fill _ _ _ (by omega)]
    have hs2l : s2.length = 128 := by
      simp only [hs2, Slice.length, Array.val_to_slice, hfull, List.length_append, List.length_take,
        hhead, hbl]; omega
    step with update_blocks_spec h st s2 (by omega) (by omega) as ⟨st1, hst1, hst1'⟩
    step as ⟨i1, hi1, hi1'⟩
    step as ⟨i2, hi2⟩
    step as ⟨i3, hi3⟩
    step as ⟨whole, rest, hwl, hrl2, hwv, hrv2⟩
    step as ⟨b, hb⟩
    have hr1 : rest1.len.val = rest1.length := by simp
    have hi1n : i1.val = rest1.length - 1 := by rw [hi1, hr1]
    have hrest1 : rest1.length ≥ 1 := by rw [← hr1]; exact hi1'
    have hwl' : whole.length = (rest1.length - 1) / 128 * 128 := by rw [hwl, hi3, hi2, hi1n]
    have hrl' : rest.length = rest1.length - (rest1.length - 1) / 128 * 128 := by
      rw [hrl2, hi3, hi2, hi1n]
    have hi3n : i3.val = (rest1.length - 1) / 128 * 128 := by rw [hi3, hi2, hi1n]
    have hpos' : bw.used.val > 0 := hpos
    have hk : ((bw.buffer.val.take bw.used.val ++ bytes.val).length - 1) / 128 * 128 = 128 + i3.val := by
      rw [hlen, hi3n]; len_omega
    step with update_blocks_if_spec h b st1 whole hb (by len_omega)
      (by rw [hst1', hs2l]; len_omega) as ⟨st2, hst2, hst2'⟩
    step as ⟨s3, back3, hsv', hsl', hback'⟩
    step as ⟨s4, hs4⟩
    have hA : (bw.buffer.val.take bw.used.val).length = bw.used.val := by simp [hbl]; omega
    have hiu : i.val + bw.used.val = 128 := by omega
    have hrest : rest.val = bytes.val.drop (i.val + i3.val) := by
      rw [hrv2, hrv, List.drop_drop, Nat.add_comm]
    have hsplit : (bw.buffer.val.take bw.used.val ++ bytes.val).take (128 + i3.val) =
        (bw.buffer.val.take bw.used.val ++ head.val) ++ whole.val := by
      rw [List.take_append, List.take_of_length_le (by omega), hA,
        show 128 + i3.val - bw.used.val = i.val + i3.val by omega, List.take_add, hhv, hwv, hrv,
        List.append_assoc]
    have hdrop : (bw.buffer.val.take bw.used.val ++ bytes.val).drop (128 + i3.val) = rest.val := by
      rw [List.drop_append, List.drop_of_length_le (by omega), List.nil_append, hA,
        show 128 + i3.val - bw.used.val = i.val + i3.val by omega, hrest]
    have hfl : (bw.buffer.val.take bw.used.val ++ head.val).length = 128 := by
      rw [List.length_append, hA]; exact (show head.val.length = i.val from hhl) ▸ (by omega)
    have hrestl : rest.val.length = rest1.val.length - i3.val := hrl2
    have hr1l : rest1.val.length = bytes.val.length - i.val := hrl
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [hk, hsplit, hst2, hst1, hs2, Array.val_to_slice, hfull]
      exact (compress_append _ _ _ (by rw [hfl])).symm
    · rw [hk, hst2', hst1', hs2l, hwl', ← hi3n]; omega
    · rw [hk, hlen, Slice.len_val]
      show rest.val.length = _
      simp only [Slice.length] at hr1l ⊢
      omega
    · have hb128 : ((back s1).val).length = 128 := (back s1).property
      rw [hk, hdrop, hback', hs4, Slice.len_val, take_setSlice!_zero _ _ (by
        rw [hb128, hrestl, hi3n]; simp only [Slice.length] at hrest1 ⊢; omega)]
  · rename_i hneg
    have hu0 : bw.used.val = 0 := by
      have : ¬ bw.used.val > 0 := hneg
      omega
    step*
    have hall : bw.buffer.val.take bw.used.val ++ bytes.val = bytes.val := by simp [hu0]
    have hi3n : i3.val = (bytes.val.length - 1) / 128 * 128 := by
      rw [i3_post, i2_post, i1_post, Slice.len_val]
    have hk : ((bw.buffer.val.take bw.used.val ++ bytes.val).length - 1) / 128 * 128 = i3.val := by
      rw [hall, hi3n]
    have hwl : whole.val.length = i3.val := whole_post
    have hrl : rest.val.length = bytes.val.length - i3.val := whole_post1
    step with update_blocks_if_spec h b st whole b_post (by rw [whole_post, hi3n]; omega)
      (by rw [whole_post, hi3n]; simp only [Slice.length, hu0] at hn ⊢; omega) as ⟨st2, hst2, hst2'⟩
    step as ⟨s3, back3, hsv', hsl', hback'⟩
    step as ⟨s4, hs4⟩
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [hk, hall, hst2, whole_post2]
    · rw [hk, hst2', whole_post]
    · rw [hk, hall, Slice.len_val]; exact hrl
    · rw [hk, hall, hback', hs4, Slice.len_val, take_setSlice!_zero _ _ (by rw [hbl, hrl, hi3n]; omega),
        whole_post3]

/-- A SHA-512 context, from initial value `iv`, that has hashed `m`: its state
is the chaining value after the whole blocks it compressed, and its buffer
holds the rest. -/
def Hashed (iv : List U64) (c : mid.sha2.Sha512Context) (m : List U8) : Prop :=
  c.blockwise.used.val ≤ 128 ∧ m.length = 128 * c.state.nblocks.val + c.blockwise.used.val ∧
    c.state.h.val = compress iv (m.take (128 * c.state.nblocks.val)) ∧
    c.blockwise.buffer.val.take c.blockwise.used.val = m.drop (128 * c.state.nblocks.val)

/-- `update` adds `bytes` to what the context has hashed. -/
theorem context_update_spec (h : RunsSha512) (iv : List U64) (c : mid.sha2.Sha512Context)
    (m : List U8) (bytes : Slice U8) (hc : Hashed iv c m) (hl : m.length + bytes.length < 2 ^ 64) :
    mid.sha2.Sha512Context.update c bytes ⦃ c' => Hashed iv c' (m ++ bytes.val) ⦄ := by
  obtain ⟨hu, hm, hh, hb⟩ := hc
  simp only [Slice.length] at hl
  unfold mid.sha2.Sha512Context.update low.generic.blockwise.Blockwise.update
  have hbl : (c.blockwise.buffer.val).length = 128 := c.blockwise.buffer.property
  have hbytes : bytes.len.val = bytes.val.length := Slice.len_val _
  have hn128 : 128 * c.state.nblocks.val ≤ m.length := by omega
  have htake : (m ++ bytes.val).take (128 * c.state.nblocks.val) = m.take (128 * c.state.nblocks.val) :=
    List.take_append_of_le_length hn128
  have hdrop : (m ++ bytes.val).drop (128 * c.state.nblocks.val) =
      m.drop (128 * c.state.nblocks.val) ++ bytes.val := List.drop_append_of_le_length hn128
  step*
  split
  · rename_i hshort
    have hshort' : bytes.val.length ≤ 128 - c.blockwise.used.val := by
      have : bytes.len.val ≤ x.val := hshort
      omega
    step as ⟨i3, hi3⟩
    step as ⟨i5, hi5⟩
    step as ⟨sb, hs, hsl, hback⟩
    obtain ⟨s, back⟩ := sb
    simp only at hs hsl hback ⊢
    step as ⟨s1, hs1⟩
    · rw [hsl, hi5, Slice.len_val]; omega
    simp only [Hashed]
    refine ⟨by omega, ?_, ?_, ?_⟩
    · simp only [List.length_append]; omega
    · rw [htake, hh]
    · rw [hdrop, ← hb, hi3, hbytes, hback, hs1]
      exact take_setSlice! c.blockwise.buffer.val bytes.val c.blockwise.used.val (by omega)
  · rename_i hlong
    have hlong' : 128 < c.blockwise.used.val + bytes.val.length := by
      have : ¬ bytes.len.val ≤ x.val := hlong
      omega
    step with sha512_complete_blocks_spec h c.blockwise bytes c.state hu hlong' (by simp only [Slice.length] at *; omega)
      as ⟨bw', st', hst, hst', hbu, hbb⟩
    rw [hb] at hst hst' hbu hbb
    generalize hA : m.drop (128 * c.state.nblocks.val) ++ bytes.val = A at hst hst' hbu hbb
    have hAl : A.length = c.blockwise.used.val + bytes.val.length := by
      rw [← hA]; simp only [List.length_append, List.length_drop]; omega
    have hk : (A.length - 1) / 128 * 128 % 128 = 0 := by omega
    have hpre : (m ++ bytes.val).take (128 * c.state.nblocks.val + (A.length - 1) / 128 * 128) =
        m.take (128 * c.state.nblocks.val) ++ A.take ((A.length - 1) / 128 * 128) := by
      rw [List.take_add, htake, hdrop, hA]
    have hsuf : (m ++ bytes.val).drop (128 * c.state.nblocks.val + (A.length - 1) / 128 * 128) =
        A.drop ((A.length - 1) / 128 * 128) := by
      rw [← List.drop_drop, hdrop, hA]
    simp only [Hashed]
    refine ⟨by omega, ?_, ?_, ?_⟩
    · rw [hst']; simp only [List.length_append]; omega
    · rw [hst', show 128 * (c.state.nblocks.val + (A.length - 1) / 128 * 128 / 128) =
          128 * c.state.nblocks.val + (A.length - 1) / 128 * 128 by omega, hpre, hst, hh,
        compress_append _ _ _ (by simp; omega)]
    · rw [hst', show 128 * (c.state.nblocks.val + (A.length - 1) / 128 * 128 / 128) =
          128 * c.state.nblocks.val + (A.length - 1) / 128 * 128 by omega, hsuf, hbb]

/-! ## Starting and finishing contexts -/

theorem sha512_initial_spec :
    mid.sha2.Sha512State.new ⦃ st => st.h.val = sha512Iv ∧ st.nblocks.val = 0 ⦄ := by
  simp [mid.sha2.Sha512State.new, mid.sha2.Sha512State.with_h, sha512Iv]

theorem sha384_initial_spec :
    mid.sha2.Sha384Context.INITIAL ⦃ st => st.h.val = sha384Iv ∧ st.nblocks.val = 0 ⦄ := by
  simp [mid.sha2.Sha384Context.INITIAL, mid.sha2.Sha512State.with_h, sha384Iv]

theorem sha512_256_initial_spec :
    mid.sha2.Sha512_256Context.INITIAL ⦃ st => st.h.val = sha512_256Iv ∧ st.nblocks.val = 0 ⦄ := by
  simp [mid.sha2.Sha512_256Context.INITIAL, mid.sha2.Sha512State.with_h, sha512_256Iv]

/-- A context resumed from an initial value has hashed nothing. -/
theorem resume_spec (iv : List U64) (st : mid.sha2.Sha512State) (hh : st.h.val = iv)
    (hn : st.nblocks.val = 0) :
    mid.sha2.Sha512Context.resume st ⦃ c => Hashed iv c [] ⦄ := by
  simp [mid.sha2.Sha512Context.resume, low.generic.blockwise.Blockwise.new, Hashed, hh, hn]

/-- `finish` is the hash of what the context has hashed. -/
theorem context_finish_spec (h : RunsSha512) (iv : List U64) (c : mid.sha2.Sha512Context)
    (m : List U8) (hc : Hashed iv c m) :
    mid.sha2.Sha512Context.finish c ⦃ r => r.val = sha512Words iv m ⦄ := by
  obtain ⟨hu, hm, hh, hb⟩ := hc
  unfold mid.sha2.Sha512Context.finish low.generic.blockwise.Blockwise.buffered
  have hbl : (c.blockwise.buffer.val).length = 128 := c.blockwise.buffer.property
  step*
  have hs : s.val = m.drop (128 * c.state.nblocks.val) := by
    rw [s_post, ← hb, List.slice]; simp
  have ht : (m.take (128 * c.state.nblocks.val)).length = 128 * c.state.nblocks.val := by
    simp; omega
  rw [r_post, hs, hh, ← compress_append _ _ _ (by rw [ht]; omega), sha512Words,
    ← List.take_append_drop (128 * c.state.nblocks.val) m, pad_append _ _ (by rw [ht]; omega),
    List.take_append_drop, ht]

theorem sha384_truncate_spec (a : Std.Array U8 64#usize) :
    mid.sha2.Sha384Context.truncate a ⦃ t => t.val = a.val.take 48 ⦄ := by
  have ha : (a.val).length = 64 := a.property
  simp [mid.sha2.Sha384Context.truncate, core.slice.Slice.first_chunk, lift, Array.to_slice, ha,
    core.option.Option.unwrap]

theorem sha512_256_truncate_spec (a : Std.Array U8 64#usize) :
    mid.sha2.Sha512_256Context.truncate a ⦃ t => t.val = a.val.take 32 ⦄ := by
  have ha : (a.val).length = 64 := a.property
  simp [mid.sha2.Sha512_256Context.truncate, core.slice.Slice.first_chunk, lift, Array.to_slice, ha,
    core.option.Option.unwrap]

/-- A digest's bytes are the value it was built from, at its algorithm's length. -/
theorem digest_new_as_ref' (alg : high.digest.Algorithm) (v : Slice U8)
    (n : Usize) (hv : high.digest.Algorithm.output_len alg = ok n) (hn : n.val = v.length)
    (h64 : v.length ≤ 64) :
    high.digest.Digest.new alg v ⦃ d =>
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d ⦃ b => b.val = v.val ⦄ ⦄ := by
  unfold high.digest.Digest.new high.digest.Digest.zeroed high.digest.Digest.as_mut
  have hlen : alg.output_len ⦃ x => x = n ⦄ := by simp [hv]
  step with hlen as ⟨x, hx⟩
  subst hx
  step as ⟨sb, hs, hsl, hback⟩
  obtain ⟨s, back⟩ := sb
  simp only at hs hsl hback ⊢
  step as ⟨s1, hs1⟩
  unfold high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref
  step with hlen as ⟨y, hy⟩
  subst hy
  step as ⟨b, hb, hbl⟩
  have hz : ((Std.Array.repeat 64#usize 0#u8).val).length = 64 := by simp
  rw [hb, Array.val_to_slice, hback, hs1, List.slice, List.drop_zero, Nat.sub_zero, hn]
  have := take_setSlice! (Std.Array.repeat 64#usize 0#u8).val v.val 0 (by simp only [Slice.length] at h64; omega)
  simpa using this

theorem digest_new_as_ref (alg : high.digest.Algorithm) (v : Slice U8)
    (n : Usize) (hv : high.digest.Algorithm.output_len alg = ok n) (hn : n.val = v.length)
    (h64 : v.length ≤ 64) :
    (do
      let d ← high.digest.Digest.new alg v
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d) ⦃ b => b.val = v.val ⦄ := by
  step with digest_new_as_ref' alg v n hv hn h64 as ⟨d, hd⟩
  exact hd

/-- `finish_with` from an initial value hashes the message. -/
theorem finish_initial_spec (h : RunsSha512) (iv : List U64) (st : mid.sha2.Sha512State)
    (hh : st.h.val = iv) (hn : st.nblocks.val = 0) (data : Slice U8) :
    mid.sha2.Sha512State.finish_with st data ⦃ r => r.val = sha512Words iv data.val ⦄ := by
  apply WP.spec_mono (finish_with_spec h st data)
  intro r hr
  rw [hr, hh, hn, sha512Words, show sha512Pad data.val = [] ++ padAfter 0 data.val from
    pad_append [] data.val rfl]
  simp

/-! ## The digest API, `high::digest`, through the modelled dispatch -/

/-- SHA-512 of `data` in one call: `digest(&SHA512, data)`'s bytes. -/
theorem sha512_digest (h : RunsSha512) (data : Slice U8) :
    (do
      let d ← high.digest.digest .SHA512 data
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d) ⦃ b => b.val = sha512 data.val ⦄ := by
  unfold high.digest.digest high.digest.Algorithm.hash high.hash.Hash.hash.default
  simp only [high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.initial,
    high.hash.Sha512State.Insts.RindHighHashHashStateSha512Context.finish_with,
    high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.ALGORITHM, high.digest.SHA512]
  step*
  step with sha512_initial_spec as ⟨st, hh, hn⟩
  step with finish_initial_spec h _ st hh hn data as ⟨r, hr⟩
  step as ⟨sl, hsl⟩
  have hl : sl.length = 64 := by simp [hsl]
  apply WP.spec_mono (digest_new_as_ref .SHA512 sl 64#usize rfl (by simp [hl]) (by simp [hl]))
  intro b hb
  rw [hb, hsl, Array.val_to_slice, hr, sha512]

/-- SHA-384 of `data` in one call: `digest(&SHA384, data)`'s bytes. -/
theorem sha384_digest (h : RunsSha512) (data : Slice U8) :
    (do
      let d ← high.digest.digest .SHA384 data
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d) ⦃ b => b.val = sha384 data.val ⦄ := by
  unfold high.digest.digest high.digest.Algorithm.hash high.hash.Hash.hash.default
  simp only [high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.initial,
    high.hash.Sha384State.Insts.RindHighHashHashStateSha384Context.finish_with,
    high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.ALGORITHM, high.digest.SHA384]
  step*
  step with sha384_initial_spec as ⟨st, hh, hn⟩
  step with finish_initial_spec h _ st hh hn data as ⟨r, hr⟩
  step with sha384_truncate_spec as ⟨t, ht⟩
  step as ⟨sl, hsl⟩
  have hl : sl.length = 48 := by simp [hsl]
  apply WP.spec_mono (digest_new_as_ref .SHA384 sl 48#usize rfl (by simp [hl]) (by simp [hl]))
  intro b hb
  rw [hb, hsl, Array.val_to_slice, ht, hr, sha384]

/-- SHA-512/256 of `data` in one call: `digest(&SHA512_256, data)`'s bytes. -/
theorem sha512_256_digest (h : RunsSha512) (data : Slice U8) :
    (do
      let d ← high.digest.digest .SHA512_256 data
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d) ⦃ b =>
      b.val = sha512_256 data.val ⦄ := by
  unfold high.digest.digest high.digest.Algorithm.hash
  simp only [high.digest.SHA512_256]
  step*
  step with sha512_256_initial_spec as ⟨st, hh, hn⟩
  step with finish_initial_spec h _ st hh hn data as ⟨r, hr⟩
  step with sha512_256_truncate_spec as ⟨t, ht⟩
  apply WP.spec_mono (digest_new_as_ref .SHA512_256 _ 32#usize rfl (by simp) (by simp))
  intro b hb
  rw [hb, Array.val_to_slice, ht, hr, sha512_256]

/-- What each SHA-512 family algorithm of the digest API computes. -/
def sha512Family : high.digest.Algorithm → Option (List U8 → List U8)
  | .SHA384 => some sha384
  | .SHA512 => some sha512
  | .SHA512_256 => some sha512_256
  | _ => none

/-- A digest context of `algorithm`, in the SHA-512 family, that has hashed `m`. -/
def ContextHashed (c : high.digest.Context) (algorithm : high.digest.Algorithm) (m : List U8) :
    Prop :=
  match c, algorithm with
  | .Sha384 hs, .SHA384 => Hashed sha384Iv hs.context.inner m
  | .Sha512 hs, .SHA512 => Hashed sha512Iv hs.context m
  | .Sha512_256 hs, .SHA512_256 => Hashed sha512_256Iv hs.context.inner m
  | _, _ => False

/-- `Context::new` starts a context that has hashed nothing. -/
theorem context_new (algorithm : high.digest.Algorithm) (f : List U8 → List U8)
    (hf : sha512Family algorithm = some f) :
    high.digest.Context.new algorithm ⦃ c => ContextHashed c algorithm [] ⦄ := by
  cases algorithm <;> simp only [sha512Family, reduceCtorEq] at hf <;>
    simp only [high.digest.Context.new, high.digest.Algorithm.start, high.digest.Hashing.start]
  · simp only [high.hash.Sha384Context.Insts.RindHighDigestVariant.NEW,
      high.hash.Sha384Context.Insts.RindHighDigestVariant.state,
      high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.new,
      mid.sha2.Sha384Context.new, mid.sha2.Sha384Context.resume]
    step with sha384_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    simpa [ContextHashed] using hc
  · simp only [high.hash.Sha512Context.Insts.RindHighDigestVariant.NEW,
      high.hash.Sha512Context.Insts.RindHighDigestVariant.state,
      high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.new,
      mid.sha2.Sha512Context.new]
    step with sha512_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    simpa [ContextHashed] using hc
  · simp only [high.digest.Sha512_256Context.Insts.RindHighDigestVariant.NEW,
      high.digest.Sha512_256Context.Insts.RindHighDigestVariant.state,
      mid.sha2.Sha512_256Context.new]
    step with sha512_256_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    simpa [ContextHashed] using hc

/-- `Context::update` adds `data` to what the context has hashed. -/
theorem context_update (h : RunsSha512) (c : high.digest.Context) (algorithm : high.digest.Algorithm)
    (m : List U8) (data : Slice U8) (hc : ContextHashed c algorithm m)
    (hl : m.length + data.length < 2 ^ 64) :
    high.digest.Context.update c data ⦃ c' => ContextHashed c' algorithm (m ++ data.val) ⦄ := by
  unfold high.digest.Context.update high.digest.State.update high.digest.Hashing.update
  rcases c with hs | hs | hs | hs | hs <;> cases algorithm <;> simp only [ContextHashed] at hc ⊢
  · simp only [high.hash.Sha384Context.Insts.RindHighHashHashContext.update, mid.sha2.Sha384Context.update]
    step with context_update_spec h _ _ _ data hc hl as ⟨c', hc'⟩
    simpa [ContextHashed] using hc'
  · simp only [high.hash.Sha512Context.Insts.RindHighHashHashContext.update]
    step with context_update_spec h _ _ _ data hc hl as ⟨c', hc'⟩
    simpa [ContextHashed] using hc'
  · simp only [high.digest.Sha512_256Context.Insts.RindHighHashHashContext.update,
      mid.sha2.Sha512_256Context.update]
    step with context_update_spec h _ _ _ data hc hl as ⟨c', hc'⟩
    simpa [ContextHashed] using hc'

/-- `Context::finish` returns the digest of what the context has hashed, and
leaves the context as `Context::new` makes it. -/
theorem context_finish (h : RunsSha512) (c : high.digest.Context) (algorithm : high.digest.Algorithm)
    (f : List U8 → List U8) (hf : sha512Family algorithm = some f) (m : List U8)
    (hc : ContextHashed c algorithm m) :
    (do
      let (d, c) ← high.digest.Context.finish c
      let b ← high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d
      ok (b, c)) ⦃ r => r.1.val = f m ∧ ContextHashed r.2 algorithm [] ⦄ := by
  unfold high.digest.Context.finish high.digest.State.finish high.digest.Hashing.finish
  rcases c with hs | hs | hs | hs | hs <;> cases algorithm <;>
    simp only [ContextHashed, sha512Family, Option.some.injEq] at hc hf ⊢ <;> subst hf
  · simp only [high.hash.Sha384Context.Insts.RindHighHashHashContext.finish, mid.sha2.Sha384Context.finish,
      high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.ALGORITHM, high.digest.SHA384]
    step*
    step with context_finish_spec h _ _ _ hc as ⟨r, hr⟩
    step with sha384_truncate_spec as ⟨t, ht⟩
    step as ⟨sl, hsl⟩
    have hl : sl.length = 48 := by simp [hsl]
    step with digest_new_as_ref' .SHA384 sl 48#usize rfl (by simp [hl]) (by simp [hl])
      as ⟨d, hd⟩
    simp only [high.hash.Sha384Context.Insts.RindHighDigestVariant.NEW,
      high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.new,
      mid.sha2.Sha384Context.new, mid.sha2.Sha384Context.resume]
    step with sha384_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    step with hd as ⟨b, hb⟩
    refine ⟨?_, by simpa using hc⟩
    rw [hb, hsl, Array.val_to_slice, ht, hr, sha384]
  · simp only [high.hash.Sha512Context.Insts.RindHighHashHashContext.finish,
      high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.ALGORITHM, high.digest.SHA512]
    step*
    step with context_finish_spec h _ _ _ hc as ⟨r, hr⟩
    step as ⟨sl, hsl⟩
    have hl : sl.length = 64 := by simp [hsl]
    step with digest_new_as_ref' .SHA512 sl 64#usize rfl (by simp [hl]) (by simp [hl])
      as ⟨d, hd⟩
    simp only [high.hash.Sha512Context.Insts.RindHighDigestVariant.NEW,
      high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.new, mid.sha2.Sha512Context.new]
    step with sha512_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    step with hd as ⟨b, hb⟩
    refine ⟨?_, by simpa using hc⟩
    rw [hb, hsl, Array.val_to_slice, hr, sha512]
  · simp only [high.digest.Sha512_256Context.Insts.RindHighHashHashContext.finish,
      mid.sha2.Sha512_256Context.finish, high.digest.SHA512_256]
    step*
    step with context_finish_spec h _ _ _ hc as ⟨r, hr⟩
    step with sha512_256_truncate_spec as ⟨t, ht⟩
    step as ⟨sl, hsl⟩
    have hl : sl.length = 32 := by simp [hsl]
    step with digest_new_as_ref' .SHA512_256 sl 32#usize rfl (by simp [hl]) (by simp [hl])
      as ⟨d, hd⟩
    simp only [high.digest.Sha512_256Context.Insts.RindHighDigestVariant.NEW,
      mid.sha2.Sha512_256Context.new]
    step with sha512_256_initial_spec as ⟨st, hh, hn⟩
    step with resume_spec _ st hh hn as ⟨c, hc⟩
    step with hd as ⟨b, hb⟩
    refine ⟨?_, by simpa using hc⟩
    rw [hb, hsl, Array.val_to_slice, ht, hr, sha512_256]

/-- Updating a context with each chunk in turn adds their concatenation. -/
theorem context_updates (h : RunsSha512) (algorithm : high.digest.Algorithm)
    (chunks : List (Slice U8)) (c : high.digest.Context) (m : List U8)
    (hc : ContextHashed c algorithm m) (hl : m.length + (chunks.flatMap (·.val)).length < 2 ^ 64) :
    chunks.foldlM high.digest.Context.update c ⦃ c' =>
      ContextHashed c' algorithm (m ++ chunks.flatMap (·.val)) ⦄ := by
  induction chunks generalizing c m with
  | nil =>
    show (ok c : Result _) ⦃ c' => ContextHashed c' algorithm (m ++ []) ⦄
    simpa [WP.spec_ok] using hc
  | cons x xs ih =>
    simp only [List.foldlM_cons, List.flatMap_cons, List.length_append] at hl ⊢
    step with context_update h c algorithm m x hc (by simp only [Slice.length]; omega) as ⟨c', hc'⟩
    apply WP.spec_mono (ih c' _ hc' (by simp only [List.length_append]; omega))
    intro r hr
    simpa [List.append_assoc] using hr

/-- The SHA-512 family through a context: `Context::new`, an `update` with each
of `chunks` in turn, and `finish` return the hash of their concatenation, for
any message shorter than 2^64 bytes, and leave the context fresh. -/
theorem sha512_family_context (h : RunsSha512) (algorithm : high.digest.Algorithm)
    (f : List U8 → List U8) (hf : sha512Family algorithm = some f) (chunks : List (Slice U8))
    (hl : (chunks.flatMap (·.val)).length < 2 ^ 64) :
    (do
      let c ← high.digest.Context.new algorithm
      let c ← chunks.foldlM high.digest.Context.update c
      let (d, c) ← high.digest.Context.finish c
      let b ← high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d
      ok (b, c)) ⦃ r =>
      r.1.val = f (chunks.flatMap (·.val)) ∧ ContextHashed r.2 algorithm [] ⦄ := by
  step with context_new algorithm f hf as ⟨c, hc⟩
  step with context_updates h algorithm chunks c [] hc (by simpa using hl) as ⟨c', hc'⟩
  simpa using context_finish h c' algorithm f hf _ hc'

/-- The SHA-512 family in one call: `digest`'s bytes are the hash of `data`. -/
theorem sha512_family_digest (h : RunsSha512) (algorithm : high.digest.Algorithm)
    (f : List U8 → List U8) (hf : sha512Family algorithm = some f) (data : Slice U8) :
    (do
      let d ← high.digest.digest algorithm data
      high.digest.Digest.Insts.CoreConvertAsRefSliceU8.as_ref d) ⦃ b => b.val = f data.val ⦄ := by
  cases algorithm <;> simp only [sha512Family, reduceCtorEq, Option.some.injEq] at hf <;> subst hf
  · exact sha384_digest h data
  · exact sha512_digest h data
  · exact sha512_256_digest h data

/-! ## The `Hash` impls, `high::hash`, as HMAC reads them -/

/-- Spec bytes as translated bytes, `bv`'s inverse. -/
def ofBv (l : List Byte) : List U8 := l.map (@UScalar.mk UScalarTy.U8)

theorem ofBv_bv (l : List U8) : ofBv (bv l) = l := by
  induction l <;> simp_all [ofBv, bv]

/-- SHA-512 over spec bytes, as `HashSpec` takes a hash. -/
def sha512Bytes (m : List Byte) : List Byte := bv (sha512 (ofBv m))

/-- SHA-384 over spec bytes, as `HashSpec` takes a hash. -/
def sha384Bytes (m : List Byte) : List Byte := bv (sha384 (ofBv m))

/-- The compression function keeps eight words: aws-lc's routine returns them. -/
theorem processBlock_length (h : RunsSha512) (hv : List U64) (hl : hv.length = 8)
    (block : List U8) (hb : block.length = 128) :
    (processBlock hv (blockWords block)).length = 8 := by
  obtain ⟨r, hr⟩ := WP.spec_exists (sha512_compress_blocks_spec h
    (Std.Array.from hv (by simp [hl])) (Slice.from block (by rw [hb]; scalar_tac)) (by
      simp [Slice.length, hb]))
  have hr' : r.val = compress hv block := by simpa using hr
  rw [compress_block _ _ (by omega), List.take_of_length_le (by omega),
    show block.drop 128 = [] by simp [hb], compress_nil] at hr'
  rw [← hr']
  simp

theorem compress_length (h : RunsSha512) (hv : List U64) (hl : hv.length = 8) (bytes : List U8) :
    (compress hv bytes).length = 8 := by
  by_cases hb : 128 ≤ bytes.length
  · rw [compress_block _ _ hb]
    exact compress_length h _ (processBlock_length h hv hl _ (by simp; omega)) _
  · rwa [compress_short _ _ (by omega)]
termination_by bytes.length
decreasing_by simp; omega

theorem sha512Words_length (h : RunsSha512) (iv : List U64) (hiv : iv.length = 8) (m : List U8) :
    (sha512Words iv m).length = 64 := by
  have h8 : ∀ a : U64, a.bv.toBEBytes.length = 8 := fun a => by simp [BitVec.toBEBytes_length]
  simp only [sha512Words, List.length_flatMap, beBytes, List.length_map, h8, List.map_const',
    List.sum_replicate, compress_length h iv hiv]
  rfl

/-- A SHA-512 state, from initial value `iv`, that has compressed `P`, a whole
number of blocks. -/
def Sha512Absorbed (iv : List U64) (P : List U8) (s : mid.sha2.Sha512State) : Prop :=
  s.h.val = compress iv P ∧ 128 * s.nblocks.val = P.length

theorem absorbed_initial (iv : List U64) (s : mid.sha2.Sha512State) (hh : s.h.val = iv)
    (hn : s.nblocks.val = 0) : Sha512Absorbed iv [] s := by
  simp [Sha512Absorbed, hh, hn]

theorem absorbed_update_blocks_spec (h : RunsSha512) (iv : List U64) (P : List U8)
    (s : mid.sha2.Sha512State) (b : Slice U8) (hs : Sha512Absorbed iv P s)
    (hb : b.length % 128 = 0) (hm : P.length + b.length ≤ maxInput) :
    mid.sha2.Sha512State.Insts.RindLowGenericBlockwiseUpdateBlocks.update_blocks s b ⦃ s' =>
      Sha512Absorbed iv (P ++ b.val) s' ⦄ := by
  obtain ⟨hh, hn⟩ := hs
  unfold maxInput at hm
  simp only [U64.max_eq, Slice.length] at hm hb
  apply WP.spec_mono (update_blocks_spec h s b hb (by simp only [Slice.length]; omega))
  rintro s' ⟨h1, h2⟩
  refine ⟨?_, ?_⟩
  · rw [h1, hh, compress_append _ _ _ (by omega)]
  · rw [h2]; simp only [Slice.length, List.length_append]; omega

theorem absorbed_finish_with_spec (h : RunsSha512) (iv : List U64) (P : List U8)
    (s : mid.sha2.Sha512State) (m : Slice U8) (hs : Sha512Absorbed iv P s) :
    mid.sha2.Sha512State.finish_with s m ⦃ r => r.val = sha512Words iv (P ++ m.val) ⦄ := by
  obtain ⟨hh, hn⟩ := hs
  have hP : P.length % 128 = 0 := by omega
  apply WP.spec_mono (finish_with_spec h s m)
  intro r hr
  rw [hr, hh, hn, ← compress_append _ _ _ hP, ← pad_append _ _ hP, sha512Words]

theorem sha512_state_clone_spec (s : mid.sha2.Sha512State) :
    mid.sha2.Sha512State.Insts.CoreCloneClone.clone s ⦃ s' => s' = s ⦄ := by
  unfold mid.sha2.Sha512State.Insts.CoreCloneClone.clone
  simp only [core.clone.impls.CloneU64.clone, lift, bind_ok]
  step*
  subst_vars
  rfl

theorem absorbed_clone_spec (iv : List U64) (P : List U8) (s : mid.sha2.Sha512State)
    (hs : Sha512Absorbed iv P s) :
    mid.sha2.Sha512State.Insts.CoreCloneClone.clone s ⦃ s' => Sha512Absorbed iv P s' ⦄ :=
  WP.spec_mono (sha512_state_clone_spec s) fun _ h => h ▸ hs

theorem absorbed_resume_spec (iv : List U64) (P : List U8) (s : mid.sha2.Sha512State)
    (hs : Sha512Absorbed iv P s) :
    mid.sha2.Sha512Context.resume s ⦃ c => Hashed iv c P ⦄ := by
  obtain ⟨hh, hn⟩ := hs
  simp [mid.sha2.Sha512Context.resume, low.generic.blockwise.Blockwise.new, Hashed, hh, hn]

theorem sha512_ctx_clone_spec (c : mid.sha2.Sha512Context) :
    mid.sha2.Sha512Context.Insts.CoreCloneClone.clone c ⦃ c' => c' = c ⦄ := by
  unfold mid.sha2.Sha512Context.Insts.CoreCloneClone.clone
  step with sha512_state_clone_spec as ⟨st, hst⟩
  step with blockwise_clone_spec as ⟨bw, hbw⟩
  subst_vars
  rfl

theorem maxInput_lt (n : Nat) (h : n ≤ maxInput) : n < 2 ^ 64 := by
  unfold maxInput at h; simp only [U64.max_eq] at h; omega

/-- SHA-512's `Hash` impl computes FIPS 180-4's SHA-512, given aws-lc's routine. -/
theorem sha512_hashSpec (h : RunsSha512) :
    HashSpec high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State sha512Bytes 128 64
      maxInput (Sha512Absorbed sha512Iv) (fun p c => Hashed sha512Iv c p) where
  out := ⟨by decide, by decide, by decide, by unfold maxInput; scalar_tac, fun m => by
    simp [sha512Bytes, bv, sha512, sha512Words_length h sha512Iv rfl]⟩
  initial := by
    simp only [high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.initial]
    step with sha512_initial_spec as ⟨s, hh, hn⟩
    exact absorbed_initial _ s hh hn
  update_blocks := fun p s b hs hb hm => by
    simp only [high.hash.Sha512State.Insts.RindHighHashHashStateSha512Context.update_blocks]
    step with absorbed_update_blocks_spec h _ p s b hs hb hm as ⟨s', h'⟩
    exact h'
  finish_with := fun p s m hs _ => by
    simp only [high.hash.Sha512State.Insts.RindHighHashHashStateSha512Context.finish_with,
      high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.ALGORITHM, high.digest.SHA512]
    step with absorbed_finish_with_spec h _ p s m hs as ⟨r, hr⟩
    step as ⟨sl, hsl⟩
    apply WP.spec_mono (digest_new_spec _ sl (by rw [hsl]; simp [outLen]))
    rintro d ⟨hd1, hd2⟩
    refine ⟨by rw [hd1]; rfl, ?_⟩
    rw [hd2, hsl, Array.val_to_slice, hr, sha512Bytes, ofBv_bv, sha512]
  clone := fun p s hs => by
    simp only [high.hash.Sha512State.Insts.CoreCloneClone.clone]
    step with absorbed_clone_spec _ p s hs as ⟨s', h'⟩
    exact h'
  resume := fun p s hs => by
    simp only [high.hash.Sha512State.Insts.RindHighHashHashStateSha512Context.resume]
    step with absorbed_clone_spec _ p s hs as ⟨s', h'⟩
    step with absorbed_resume_spec _ p s' h' as ⟨c, hc⟩
    exact hc
  update := fun p c b hc hm => by
    simp only [high.hash.Sha512Context.Insts.RindHighHashHashContext.update]
    step with context_update_spec h _ c p b hc (maxInput_lt _ hm) as ⟨c', h'⟩
    exact h'
  finish := fun p c hc _ => by
    simp only [high.hash.Sha512Context.Insts.RindHighHashHashContext.finish,
      high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.ALGORITHM, high.digest.SHA512]
    step with context_finish_spec h _ c p hc as ⟨r, hr⟩
    step as ⟨sl, hsl⟩
    apply WP.spec_mono (digest_new_spec _ sl (by rw [hsl]; simp [outLen]))
    rintro d ⟨hd1, hd2⟩
    refine ⟨by rw [hd1]; rfl, ?_⟩
    rw [hd2, hsl, Array.val_to_slice, hr, sha512Bytes, ofBv_bv, sha512]
  zeroed_block := by
    simp only [high.hash.Sha512.Insts.RindHighHashHashSha512ContextSha512State.zeroed_block,
      high.hash.HashBlock.new, mid.sha2.Sha512Context.BLOCK_SZ]
    simp
  hash_default := rfl
  cclone := fun p c hc => by
    simp only [high.hash.Sha512Context.Insts.CoreCloneClone.clone]
    step with sha512_ctx_clone_spec as ⟨c', h'⟩
    exact h' ▸ hc

/-- SHA-384's `Hash` impl computes FIPS 180-4's SHA-384, given aws-lc's routine. -/
theorem sha384_hashSpec (h : RunsSha512) :
    HashSpec high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State sha384Bytes 128 48
      maxInput (Sha512Absorbed sha384Iv) (fun p c => Hashed sha384Iv c.inner p) where
  out := ⟨by decide, by decide, by decide, by unfold maxInput; scalar_tac, fun m => by
    simp [sha384Bytes, bv, sha384, sha512Words_length h sha384Iv rfl]⟩
  initial := by
    simp only [high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.initial]
    step with sha384_initial_spec as ⟨s, hh, hn⟩
    exact absorbed_initial _ s hh hn
  update_blocks := fun p s b hs hb hm => by
    simp only [high.hash.Sha384State.Insts.RindHighHashHashStateSha384Context.update_blocks]
    step with absorbed_update_blocks_spec h _ p s b hs hb hm as ⟨s', h'⟩
    exact h'
  finish_with := fun p s m hs _ => by
    simp only [high.hash.Sha384State.Insts.RindHighHashHashStateSha384Context.finish_with,
      high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.ALGORITHM, high.digest.SHA384]
    step with absorbed_finish_with_spec h _ p s m hs as ⟨r, hr⟩
    step with sha384_truncate_spec as ⟨t, ht⟩
    step as ⟨sl, hsl⟩
    apply WP.spec_mono (digest_new_spec _ sl (by rw [hsl]; simp [outLen]))
    rintro d ⟨hd1, hd2⟩
    refine ⟨by rw [hd1]; rfl, ?_⟩
    rw [hd2, hsl, Array.val_to_slice, ht, hr, sha384Bytes, ofBv_bv, sha384]
  clone := fun p s hs => by
    simp only [high.hash.Sha384State.Insts.CoreCloneClone.clone]
    step with absorbed_clone_spec _ p s hs as ⟨s', h'⟩
    exact h'
  resume := fun p s hs => by
    simp only [high.hash.Sha384State.Insts.RindHighHashHashStateSha384Context.resume,
      mid.sha2.Sha384Context.resume]
    step with absorbed_clone_spec _ p s hs as ⟨s', h'⟩
    step with absorbed_resume_spec _ p s' h' as ⟨c, hc⟩
    exact hc
  update := fun p c b hc hm => by
    simp only [high.hash.Sha384Context.Insts.RindHighHashHashContext.update,
      mid.sha2.Sha384Context.update]
    step with context_update_spec h _ c.inner p b hc (maxInput_lt _ hm) as ⟨c', h'⟩
    exact h'
  finish := fun p c hc _ => by
    simp only [high.hash.Sha384Context.Insts.RindHighHashHashContext.finish,
      mid.sha2.Sha384Context.finish,
      high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.ALGORITHM, high.digest.SHA384]
    step with context_finish_spec h _ c.inner p hc as ⟨r, hr⟩
    step with sha384_truncate_spec as ⟨t, ht⟩
    step as ⟨sl, hsl⟩
    apply WP.spec_mono (digest_new_spec _ sl (by rw [hsl]; simp [outLen]))
    rintro d ⟨hd1, hd2⟩
    refine ⟨by rw [hd1]; rfl, ?_⟩
    rw [hd2, hsl, Array.val_to_slice, ht, hr, sha384Bytes, ofBv_bv, sha384]
  zeroed_block := by
    simp only [high.hash.Sha384.Insts.RindHighHashHashSha384ContextSha384State.zeroed_block,
      high.hash.HashBlock.new, mid.sha2.Sha512Context.BLOCK_SZ]
    simp
  hash_default := rfl
  cclone := fun p c hc => by
    simp only [high.hash.Sha384Context.Insts.CoreCloneClone.clone,
      mid.sha2.Sha384Context.Insts.CoreCloneClone.clone]
    step with sha512_ctx_clone_spec as ⟨c', h'⟩
    exact h' ▸ hc

end rind.x86_64
