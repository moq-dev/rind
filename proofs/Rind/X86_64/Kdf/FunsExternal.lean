module
public import Rind.X86_64.HkdfExpand
@[expose] public section
open Aeneas Aeneas.Std Result
set_option linter.dupNamespace false

/-! The functions the x86_64 HKDF and PBKDF2 translation leaves opaque, beside
the HMAC API's, which `Rind.X86_64.HmacDispatch` models, and HKDF-Expand's
loop, which `Rind.X86_64.HkdfExpand` does: each as the Rust standard library
or rind defines it. -/

namespace rind.x86_64.kdf

/-- `NonZeroU32Inner`'s `Clone`. -/
def core.num.niche_types.NonZeroU32Inner.Insts.CoreCloneClone.clone
    (x : core.num.niche_types.NonZeroU32Inner) : Result core.num.niche_types.NonZeroU32Inner :=
  ok x

/-- `NonZero::get`. -/
def core.num.nonzero.NonZero.get {T Inner : Type}
    (_ : core.num.nonzero.ZeroablePrimitive T Inner) (x : core.num.nonzero.NonZero T Inner) :
    Result T :=
  ok x

/-- `Digest`'s derived `Clone`, which copies its algorithm and bytes. -/
def high.digest.Digest.Insts.CoreCloneClone.clone (d : high.digest.Digest) :
    Result high.digest.Digest :=
  ok d

end rind.x86_64.kdf
