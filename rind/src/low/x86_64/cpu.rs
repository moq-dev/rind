// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) fn enter_cpu_state() -> u32 {
    // DOIT: "Data Operand Independent Timing" -- turning this on
    // is under kernel control, because MSRs are privileged.
    // <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html>
    0
}

/// Nothing to restore, since `enter_cpu_state` changed nothing. Vector
/// registers hold scratch, not owned secrets, so like aws-lc we leave them.
pub(crate) fn leave_cpu_state(_old: u32) {}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety
/// The caller must ensure that there are `len` bytes writable at `ptr`,
/// and that the pointed-to object has a safe all-zeroes representation.
/// (see `low::generic::zeroise` which expresses this within the type system).
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: this crate requires the `avx` cpu feature
    unsafe { _zero_bytes(ptr, len) }
}

#[target_feature(enable = "avx,avx2")]
unsafe fn _zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: writes to `len` bytes at `ptr`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "       vpxor   {zero}, {zero}, {zero}",
            // by-32 loop
            "   2:  cmp {len}, 32",
            "       jl  3f",
            "       vmovdqu [{ptr}], {zero}",
            "       add {ptr}, 32",
            "       sub {len}, 32",
            "       jmp 2b",
            // by-1 loop
            "   3:  sub {len}, 1",
            "       jl  4f",
            "       mov byte ptr [{ptr}], 0",
            "       add {ptr}, 1",
            "       jmp 3b",
            "   4:  ",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,

            // clobbers
            zero = out(ymm_reg) _,
        )
    }
}

/// Effectively memcmp(a, b, len), but guaranteed to visit every element
/// of a and b.
///
/// The return value does not follow memcmp semantics: it is zero if
/// `a == b`, otherwise it is non-zero.
///
/// # Safety
/// The caller must ensure that there are `len` bytes readable at `a` and `b`,
pub(in crate::low) unsafe fn ct_compare_bytes(a: *const u8, b: *const u8, len: usize) -> u8 {
    let mut acc = 0u8;
    // SAFETY: reads `len` bytes from `a` and `b`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "   2: cmp {len}, 0",
            "      je  3f",
            "      mov {tmp}, [{a}]",
            "      xor {tmp}, [{b}]",
            "      or  {acc}, {tmp}",
            "      add {a}, 1",
            "      add {b}, 1",
            "      sub {len}, 1",
            "      jmp 2b",
            "   3:  ",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            tmp = inout(reg_byte) 0u8 => _,
            acc = inout(reg_byte) acc,
        );
    }
    acc
}

/// Token type reflecting the check for CPU features needed for AVX512-AES-GCM
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveAvx512ForAesGcm(());

impl HaveAvx512ForAesGcm {
    pub(crate) fn check() -> Option<Self> {
        match has(AVX512F | AVX512BW | AVX512VL | VPCLMULQDQ | VAES) {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for VAES-AES-GCM
/// on 256-bit vectors, beyond the AVX2 this crate requires.
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveVaesAvx2ForAesGcm(());

impl HaveVaesAvx2ForAesGcm {
    pub(crate) fn check() -> Option<Self> {
        match has(VPCLMULQDQ | VAES) {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for AVX512-ML-KEM
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveAvx512ForMlKem(());

impl HaveAvx512ForMlKem {
    pub(crate) fn check() -> Option<Self> {
        match has(AVX512F | AVX512BW | AVX512VBMI | AVX512VBMI2) {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for SHA1 using SHA-NI
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha1(());

impl HaveSha1 {
    pub(crate) fn check() -> Option<Self> {
        match has(SHA) {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for SHA256 using SHA-NI
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha256(());

impl HaveSha256 {
    pub(crate) fn check() -> Option<Self> {
        match has(SHA) {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Proof that the CPU has BMI2 and ADX, which s2n-bignum's fastest x86_64
/// routines use (`mulx`, `adcx`, and `adox`).
///
/// Without them, each routine's `_alt` twin runs instead.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveBmi2Adx(());

impl HaveBmi2Adx {
    pub(crate) fn check() -> Option<Self> {
        has(BMI2 | ADX).then_some(Self(()))
    }
}

/// Whether the CPU is Intel's, for code that is fastest on one vendor's cores.
pub(crate) fn is_intel() -> bool {
    has(INTEL)
}

const AES: u32 = 1 << 0;
const VAES: u32 = 1 << 1;
const PCLMULQDQ: u32 = 1 << 2;
const VPCLMULQDQ: u32 = 1 << 3;
const BMI2: u32 = 1 << 4;
const ADX: u32 = 1 << 5;
const POPCNT: u32 = 1 << 6;
const SSSE3: u32 = 1 << 7;
const AVX: u32 = 1 << 8;
const AVX2: u32 = 1 << 9;
const AVX512F: u32 = 1 << 10;
const AVX512BW: u32 = 1 << 11;
const AVX512VL: u32 = 1 << 12;
const AVX512VBMI: u32 = 1 << 13;
const AVX512VBMI2: u32 = 1 << 14;
const SHA: u32 = 1 << 15;
const INTEL: u32 = 1 << 30;
const DETECTED: u32 = 1 << 31;

/// Whether the CPU has every feature in `wanted`.
fn has(wanted: u32) -> bool {
    features() & wanted == wanted
}

/// The detected features, read once: `cpuid` is slow, and traps to the
/// hypervisor in a VM.
fn features() -> u32 {
    static FEATURES: AtomicU32 = AtomicU32::new(0);

    match FEATURES.load(Ordering::Relaxed) {
        0 => {
            let features = detect() | DETECTED;
            FEATURES.store(features, Ordering::Relaxed);
            features
        }
        features => features,
    }
}

fn detect() -> u32 {
    macro_rules! detect {
        ($name:tt, $bit:expr) => {
            if test_toggle($name, is_x86_feature_detected!($name)) {
                $bit
            } else {
                0
            }
        };
    }

    // "GenuineIntel", spread over ebx, edx, and ecx.
    let id = __cpuid(0);
    let intel = (id.ebx, id.edx, id.ecx) == (0x756e_6547, 0x4965_6e69, 0x6c65_746e);

    // Valgrind runs ADX instructions but hides them from `cpuid`
    // (https://bugs.kde.org/show_bug.cgi?id=494162), so `admin/ctgrind` builds
    // with this switch to check the ADX routines rather than their `_alt`
    // twins.
    let adx = is_x86_feature_detected!("adx") || option_env!("VALGRIND_BUG_494162").is_some();

    (if test_toggle("intel", intel) {
        INTEL
    } else {
        0
    }) | (if test_toggle("adx", adx) { ADX } else { 0 })
        | detect!("aes", AES)
        | detect!("vaes", VAES)
        | detect!("pclmulqdq", PCLMULQDQ)
        | detect!("vpclmulqdq", VPCLMULQDQ)
        | detect!("bmi2", BMI2)
        | detect!("popcnt", POPCNT)
        | detect!("ssse3", SSSE3)
        | detect!("avx", AVX)
        | detect!("avx2", AVX2)
        | detect!("avx512f", AVX512F)
        | detect!("avx512bw", AVX512BW)
        | detect!("avx512vl", AVX512VL)
        | detect!("avx512vbmi", AVX512VBMI)
        | detect!("avx512vbmi2", AVX512VBMI2)
        | detect!("sha", SHA)
}

#[cfg(not(debug_assertions))]
fn test_toggle(_id: &str, detected: bool) -> bool {
    detected
}

/// Lets a debug build deny a feature with `RIND_CPU_DISABLE_<id>`, so a CPU
/// with it also tests the code for one without.
#[cfg(debug_assertions)]
fn test_toggle(id: &str, detected: bool) -> bool {
    if std::env::var(format!("RIND_CPU_DISABLE_{id}")).is_ok() {
        println!("DEBUG: denying cpuid {id:?}");
        false
    } else {
        detected
    }
}

/// Returns the first CPU feature we require unconditionally that this CPU lacks.
///
/// This limits the library to x86_64 processors released after approx 2014.
/// Ordered oldest first, so the name points at the real gap. `sse3` and
/// `sse4.1` are implied by `avx` in rustc's feature model.
pub(crate) fn missing_cpu_feature() -> Option<&'static str> {
    // assorted intrinsic code
    if !has(SSSE3) {
        return Some("ssse3");
    }
    // ML-KEM rejection sampling
    if !has(POPCNT) {
        return Some("popcnt");
    }
    // our aes-gcm
    if !has(AES) {
        return Some("aes");
    }
    if !has(PCLMULQDQ) {
        return Some("pclmulqdq");
    }
    // assorted intrinsic code
    if !has(AVX) {
        return Some("avx");
    }
    if !has(AVX2) {
        return Some("avx2");
    }
    None
}

// --- Safe abstractions over common intrinsics operations ---

/// Prefetch both `table` and `table[stride]`
///
/// `table[stride]` is not range checked, as prefetching doesn't need a valid
/// pointer.
#[target_feature(enable = "sse")]
#[inline]
pub(crate) fn prefetch<T>(table: &[T], stride: usize) {
    // SAFETY: prefetches do not fault and are not architecturally visible
    unsafe {
        _mm_prefetch(table.as_ptr().cast(), _MM_HINT_T0);
        _mm_prefetch(table.as_ptr().add(stride).cast(), _MM_HINT_T0);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // CI runs the suite again with features denied, and names the path each
    // run expects, so no run silently tests only the fastest one.
    #[test]
    fn detects_the_expected_cpu() {
        if let Some(expected) = std::env::var_os("RIND_TEST_X86_BMI2_ADX") {
            assert_eq!(HaveBmi2Adx::check().is_some(), expected == "1");
        }
    }
}
