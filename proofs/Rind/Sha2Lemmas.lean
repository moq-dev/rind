import Rind.Sha2
open Aeneas Aeneas.Std

/-! Facts about `Rind.Sha2`'s spec that the proofs use. -/

namespace rind.spec

/-- No slice reaches 2^64 elements. -/
theorem slice_length_lt {α : Type _} (s : Slice α) : s.length < 2 ^ 64 := by
  have := s.property
  rcases Usize.bounds_eq with h | h <;> simp only [Slice.length, h] at this ⊢ <;> scalar_tac

theorem compress_short (h : List U64) (bytes : List U8) (hb : bytes.length < 128) :
    compress h bytes = h := by
  rw [compress]; simp [show ¬ 128 ≤ bytes.length by omega]

@[simp] theorem compress_nil (h : List U64) : compress h [] = h :=
  compress_short h [] (by simp)

theorem compress_block (h : List U64) (bytes : List U8) (hb : 128 ≤ bytes.length) :
    compress h bytes = compress (processBlock h (blockWords (bytes.take 128))) (bytes.drop 128) := by
  rw [compress]; simp [hb]

/-- Compressing whole blocks, then more, is compressing them all. -/
theorem compress_append (h : List U64) (a b : List U8) (ha : a.length % 128 = 0) :
    compress h (a ++ b) = compress (compress h a) b := by
  by_cases hl : a.length = 0
  · simp [List.eq_nil_of_length_eq_zero hl]
  · have h128 : 128 ≤ a.length := by omega
    rw [compress_block h (a ++ b) (by simp; omega), compress_block h a h128,
      List.take_append_of_le_length h128, List.drop_append_of_le_length h128]
    exact compress_append _ _ _ (by simp; omega)
termination_by a.length
decreasing_by simp; omega

/-- `m` padded as the end of a message whose first `k` bytes came before it. -/
def padAfter (k : Nat) (m : List U8) : List U8 :=
  m ++ 0x80#u8 :: List.replicate ((239 - m.length % 128) % 128) 0#u8 ++
    (BitVec.ofNat 128 (8 * (k + m.length))).toBEBytes.map (@UScalar.mk UScalarTy.U8)

/-- Padding a message after whole blocks pads its rest. -/
theorem pad_append (p m : List U8) (hp : p.length % 128 = 0) :
    sha512Pad (p ++ m) = p ++ padAfter p.length m := by
  simp only [sha512Pad, padAfter, List.length_append, List.append_assoc,
    show (p.length + m.length) % 128 = m.length % 128 by omega]

end rind.spec
