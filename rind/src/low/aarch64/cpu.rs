// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::sync::atomic::{AtomicU8, Ordering};

pub(crate) fn enter_cpu_state() -> u32 {
    dit::maybe_enable()
}

pub(crate) fn leave_cpu_state(old: u32) {
    dit::maybe_disable(old);
}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety:
/// There must be `len` writable bytes at `ptr`; with no alignment
/// requirement.
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: inline assembly.
    unsafe {
        core::arch::asm!(
            "       eor {zero}.16b, {zero}.16b, {zero}.16b",
            // by-16 loop
            "   2:  cmp {len}, #16",
            "       blt 3f",
            "       st1 {{{zero}.16b}}, [{ptr}]",
            "       add {ptr}, {ptr}, #16",
            "       sub {len}, {len}, #16",
            "       b 2b",
            // by-8 loop
            "   3:  cmp {len}, #8",
            "       blt 4f",
            "       str xzr, [{ptr}], #8",
            "       sub {len}, {len}, #8",
            "       b 3b",
            // by-1 loop
            "   4:  subs {len}, {len}, #1",
            "       blt 5f",
            "       strb wzr, [{ptr}], #1",
            "       b 4b",
            "   5:  ",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,

            // clobbers
            zero = out(vreg) _,
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
    // SAFETY: inline assembly.
    unsafe {
        let mut acc = 0u8;
        core::arch::asm!(
            "   2: cmp  {len}, 0",
            "      beq  3f",
            "      ldrb {tmpa:w}, [{a}]",
            "      ldrb {tmpb:w}, [{b}]",
            "      eor  {tmpa:w}, {tmpa:w}, {tmpb:w}",
            "      orr  {acc:w}, {acc:w}, {tmpa:w}",
            "      add  {a}, {a}, 1",
            "      add  {b}, {b}, 1",
            "      sub  {len}, {len}, 1",
            "      b    2b",
            "   3:  ",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            tmpa = inout(reg) 0u8 => _,
            tmpb = inout(reg) 0u8 => _,
            acc = inout(reg) acc,
        );
        acc
    }
}

/// Compares two 16-byte blocks, such as AEAD tags, in constant time.
///
/// Returns zero if `a == b`, otherwise non-zero. The words are combined in
/// assembly so the compiler cannot split the test into early exits.
pub(in crate::low) fn ct_compare_16(a: &[u8; 16], b: &[u8; 16]) -> usize {
    let (a, b) = (u128::from_ne_bytes(*a), u128::from_ne_bytes(*b));
    let mut diff = a as u64;
    // SAFETY: register-only arithmetic.
    unsafe {
        core::arch::asm!(
            "eor {diff}, {diff}, {b0}",
            "eor {a1}, {a1}, {b1}",
            "orr {diff}, {diff}, {a1}",
            diff = inout(reg) diff,
            a1 = inout(reg) (a >> 64) as u64 => _,
            b0 = in(reg) b as u64,
            b1 = in(reg) (b >> 64) as u64,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    diff as usize
}

/// Proof that the CPU has the crypto extension: AES, PMULL, SHA-1, and
/// SHA-256.
///
/// Cores without it (such as the Raspberry Pi 4's Cortex-A72) lack all of it,
/// so one token covers it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveCryptoExt(());

impl HaveCryptoExt {
    /// Detects the extension once, then answers from the cached result.
    pub(crate) fn check() -> Option<Self> {
        (features() & CRYPTO_EXT != 0).then_some(Self(()))
    }
}

/// Token type reflecting the check for the SHA3 CPU feature
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha3(());

impl HaveSha3 {
    pub(crate) fn check() -> Option<Self> {
        (features() & SHA3 != 0).then_some(Self(()))
    }
}

/// Returns the first CPU feature we require unconditionally that this CPU lacks.
pub(crate) fn missing_cpu_feature() -> Option<&'static str> {
    (features() & NEON == 0).then_some("neon")
}

const NEON: u8 = 1 << 0;
const CRYPTO_EXT: u8 = 1 << 1;
const SHA3: u8 = 1 << 2;
const DIT: u8 = 1 << 3;
const DETECTED: u8 = 1 << 7;

static FEATURES: AtomicU8 = AtomicU8::new(0);

/// The detected features, read once. Inlined, so a check is a load and a
/// test, with the first call's detection out of line.
#[inline]
fn features() -> u8 {
    match FEATURES.load(Ordering::Relaxed) {
        0 => detect_once(),
        features => features,
    }
}

#[cold]
#[inline(never)]
fn detect_once() -> u8 {
    let features = detect() | DETECTED;
    FEATURES.store(features, Ordering::Relaxed);
    features
}

fn detect() -> u8 {
    use std::arch::is_aarch64_feature_detected as detected;

    let neon = test_toggle("neon", detected!("neon"));
    let crypto_ext = test_toggle("aes", detected!("aes"))
        && test_toggle("pmull", detected!("pmull"))
        // Rust's `sha2` covers the SHA-1 instructions too.
        && test_toggle("sha2", detected!("sha2"));
    let sha3 = test_toggle("sha3", detected!("sha3"));
    #[cfg(not(any(windows, target_os = "linux")))]
    let dit = test_toggle("dit", detected!("dit"));
    #[cfg(target_os = "linux")]
    let dit = test_toggle(
        "dit",
        detected!("dit") || linux::cores_have_dit() == Some(true),
    );
    #[cfg(windows)]
    let dit = test_toggle("dit", windows::executes_dit());
    (if neon { NEON } else { 0 })
        | (if crypto_ext { CRYPTO_EXT } else { 0 })
        | (if sha3 { SHA3 } else { 0 })
        | (if dit { DIT } else { 0 })
}

/// Hyper-V hides DIT from Linux too, so the kernel reports none on a core that
/// has it, such as Azure's Cobalt 100. It passes each core's `MIDR_EL1`
/// through, though, so this reads which core models the kernel can run on.
/// Probing the instruction instead would need a process-wide SIGILL handler.
#[cfg(target_os = "linux")]
mod linux {
    /// Whether every core the kernel can run on has DIT, or `None` if it can't
    /// tell, without a readable `/sys` or with a CPU offline.
    pub(super) fn cores_have_dit() -> Option<bool> {
        let read = |file: &str| std::fs::read_to_string(format!("/sys/devices/system/cpu/{file}"));
        all_cores_have_dit(&read("possible").ok()?, |cpu| {
            let midr = read(&format!("cpu{cpu}/regs/identification/midr_el1")).ok()?;
            u64::from_str_radix(midr.trim().strip_prefix("0x")?, 16).ok()
        })
    }

    /// Whether every CPU in `possible`, the kernel's list of CPUs it may
    /// bring online, such as `0-3,8-11`, has a `MIDR_EL1` naming a core with
    /// DIT. One offline now has no `MIDR_EL1` to read, so the answer is `None`.
    pub(super) fn all_cores_have_dit(
        possible: &str,
        midr: impl Fn(u32) -> Option<u64>,
    ) -> Option<bool> {
        for range in possible.trim().split(',') {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            let (first, last) = (first.parse::<u32>().ok()?, last.parse::<u32>().ok()?);
            if first > last {
                return None;
            }
            for cpu in first..=last {
                if !has_dit(midr(cpu)?) {
                    return Some(false);
                }
            }
        }
        Some(true)
    }

    /// Whether the core this `MIDR_EL1` names has DIT, which Armv8.4 made
    /// mandatory: the cores Linux's `arch/arm64/include/asm/cputype.h` names
    /// that implement Armv8.4 or later.
    fn has_dit(midr: u64) -> bool {
        let implementer = (midr >> 24) & 0xff;
        let part = (midr >> 4) & 0xfff;
        match implementer {
            // Arm's, all but the Armv8.2 Cortex-A78, A78C, X1, and X1C
            // numbered among them.
            0x41 => matches!(
                part,
                0xd40 // Neoverse V1
                | 0xd46 // Cortex-A510
                | 0xd47 // Cortex-A710
                | 0xd48 // Cortex-X2
                | 0xd49 // Neoverse N2
                | 0xd4d // Cortex-A715
                | 0xd4e // Cortex-X3
                | 0xd4f // Neoverse V2
                | 0xd80 // Cortex-A520
                | 0xd81 // Cortex-A720
                | 0xd82 // Cortex-X4
                | 0xd83 // Neoverse V3AE
                | 0xd84 // Neoverse V3
                | 0xd85 // Cortex-X925
                | 0xd87 // Cortex-A725
                | 0xd88 // Cortex-A520AE
                | 0xd89 // Cortex-A720AE
                | 0xd8a // C1-Nano
                | 0xd8b // C1-Pro
                | 0xd8c // C1-Ultra
                | 0xd8e // Neoverse N3
                | 0xd90 // C1-Premium
            ),
            // Qualcomm's Oryon, as in the Snapdragon X, where WSL runs Linux
            // under Hyper-V.
            0x51 => part == 0x001,
            _ => false,
        }
    }
}

/// Windows publishes no DIT flag: `IsProcessorFeaturePresent`, which Rust's
/// detection reads, has none, and the copy of `ID_AA64PFR0_EL1` in the
/// registry reads DIT as absent under Hyper-V even on a core that has it, such
/// as Azure's Cobalt 100. So this runs `mrs DIT` and catches the illegal
/// instruction a core without DIT raises.
#[cfg(windows)]
mod windows {
    use core::cell::Cell;
    use core::ffi::c_void;

    pub(super) fn executes_dit() -> bool {
        probe(|| {
            let ran: u64;
            // SAFETY: reads PSTATE.DIT, spelled as its encoding since the
            // assembler names it only for `dit` code, or raises the illegal
            // instruction `skip_probe` resumes past.
            unsafe {
                core::arch::asm!(
                    "mrs x1, S3_3_C4_C2_5",
                    "mov x0, #1",
                    out("x0") ran,
                    out("x1") _,
                    // No `nomem`: `PROBING` must be set before this runs.
                    options(nostack, preserves_flags),
                );
            }
            ran
        })
    }

    /// Runs `run`, whose asm executes one instruction that may be illegal and
    /// then `mov x0, #1`, returning whether the instruction ran.
    pub(super) fn probe(run: impl FnOnce() -> u64) -> bool {
        // SAFETY: `skip_probe` is a vectored exception handler, and stays
        // valid for the life of the process.
        let handler = unsafe { AddVectoredExceptionHandler(1, skip_probe) };
        assert!(!handler.is_null(), "AddVectoredExceptionHandler failed");
        PROBING.set(true);
        let ran = run();
        PROBING.set(false);
        // SAFETY: `handler` was registered above and not yet removed.
        unsafe { RemoveVectoredExceptionHandler(handler) };
        ran == 1
    }

    std::thread_local! {
        // Set while this thread runs a probe, so the handler, which sees every
        // thread's exceptions, resumes only the probe.
        static PROBING: Cell<bool> = const { Cell::new(false) };
    }

    const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    /// The head of `EXCEPTION_RECORD`.
    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
    }

    /// The head of the aarch64 `CONTEXT`.
    #[repr(C)]
    struct Context {
        _flags_and_cpsr: u64,
        x: [u64; 31],
        _sp: u64,
        pc: u64,
    }

    #[repr(C)]
    struct ExceptionPointers {
        record: *const ExceptionRecord,
        context: *mut Context,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;
        fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    }

    /// Resumes a probe whose instruction is illegal after its `mov x0, #1`,
    /// with x0 zeroed.
    unsafe extern "system" fn skip_probe(info: *mut ExceptionPointers) -> i32 {
        // SAFETY: Windows passes the faulting thread's exception record and
        // the context it resumes.
        let (record, context) = unsafe { (&*(*info).record, &mut *(*info).context) };
        if record.code != STATUS_ILLEGAL_INSTRUCTION || !PROBING.get() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        context.x[0] = 0;
        context.pc += 8;
        EXCEPTION_CONTINUE_EXECUTION
    }
}

mod dit {
    pub(super) fn maybe_enable() -> u32 {
        if super::features() & super::DIT != 0 {
            // SAFETY: in this branch, we verified `dit` cpu feature is supported
            match unsafe { read() } {
                0 => {
                    // SAFETY: in this branch, we verified `dit` cpu feature is supported
                    unsafe {
                        write(1);
                    };
                    1
                }
                _ => 0,
            }
        } else {
            0
        }
    }

    pub(super) fn maybe_disable(we_enabled: u32) {
        if we_enabled > 0 {
            // SAFETY: `we_enabled > 0` implies `dit` cpu feature was supported earlier
            unsafe { write(0) }
        }
    }

    #[target_feature(enable = "dit")]
    pub(super) fn read() -> u32 {
        let mut out: u64;
        // SAFETY: `mrs _, DIT` is defined only if `dit` cpu feature is supported
        unsafe {
            core::arch::asm!(
                "mrs {r}, DIT",
                r = out(reg) out,
            );
        }

        const DIT: u64 = 0x01000000;
        (out & DIT == DIT) as u32
    }

    #[target_feature(enable = "dit")]
    pub(super) fn write(on: u32) {
        if on > 0 {
            // SAFETY: `msr DIT, _` is defined only if `dit` cpu feature is supported
            unsafe { core::arch::asm!("msr DIT, #1") }
        } else {
            // SAFETY: `msr DIT, _` is defined only if `dit` cpu feature is supported
            unsafe { core::arch::asm!("msr DIT, #0") }
        }
    }
}

#[cfg(not(any(debug_assertions, rind_cpu_disable)))]
fn test_toggle(_id: &str, detected: bool) -> bool {
    detected
}

/// Lets a debug build, or a release one with `--cfg rind_cpu_disable`, deny a
/// feature with `RIND_CPU_DISABLE_<id>`, as on x86_64, so a CPU with the
/// crypto extension also tests the code for one without.
#[cfg(any(debug_assertions, rind_cpu_disable))]
fn test_toggle(id: &str, detected: bool) -> bool {
    if std::env::var(format!("RIND_CPU_DISABLE_{id}")).is_ok() {
        println!("DEBUG: denying cpuid {id:?}");
        false
    } else {
        detected
    }
}

/// Read-only prefetch hint.
pub(in crate::low) fn prefetch_ro<T>(ptr: *const T) {
    // SAFETY: inline assembly
    unsafe {
        core::arch::asm!(
            "prfm pldl1strm, [{ptr}]",
            ptr = in(reg) ptr,
            options(readonly, nostack)
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Whether std detects every feature named, less those
    /// `RIND_CPU_DISABLE_*` denies.
    macro_rules! available {
        ($($name:tt),+) => {
            true $(&& std::arch::is_aarch64_feature_detected!($name)
                && std::env::var_os(concat!("RIND_CPU_DISABLE_", $name)).is_none())+
        };
    }

    // Each check names the features its kernels need, which the OS reports
    // independently of the bits `detect` packs them into.
    #[test]
    fn checks_need_their_features() {
        assert_eq!(missing_cpu_feature().is_none(), available!("neon"));
        assert_eq!(
            HaveCryptoExt::check().is_some(),
            available!("aes", "pmull", "sha2")
        );
        assert_eq!(HaveSha3::check().is_some(), available!("sha3"));
    }

    // CI runs the aarch64 suite on a CPU with the crypto extension, then
    // again with it denied, and names which, so neither run silently tests
    // only one path.
    #[test]
    fn detects_the_expected_cpu() {
        if let Some(expected) = std::env::var_os("RIND_TEST_ARM_CRYPTO_EXT") {
            assert_eq!(HaveCryptoExt::check().is_some(), expected == "1");
        }
    }

    // A core that runs `mrs DIT` has DIT, whatever its OS reports, so a
    // child process runs it. Where Linux hides DIT, rind can't tell the core
    // without `/sys` or with a CPU offline, as PLATFORMS.md states, so the test
    // can't either; a core missing from the table still fails it. Android's
    // kernels report DIT, and rind trusts that report there, so the test does
    // too.
    #[test]
    fn enables_dit_whenever_the_cpu_has_it() {
        #[cfg(target_os = "linux")]
        let has_dit = child_reads_dit()
            && (std::arch::is_aarch64_feature_detected!("dit")
                || linux::cores_have_dit().is_some());
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let has_dit = child_reads_dit();
        #[cfg(target_os = "android")]
        let has_dit = std::arch::is_aarch64_feature_detected!("dit");

        let expected = test_toggle("dit", has_dit);
        assert_eq!(features() & DIT != 0, expected);
        // A denied DIT is left alone, as under `admin/ctgrind`, whose
        // valgrind runs no DIT instruction.
        if expected {
            // SAFETY: this core has DIT. Cleared, so only an `Entry` can set
            // it.
            unsafe { dit::write(0) };
            let outer = crate::low::Entry::new_secret();
            // SAFETY: as above.
            assert_eq!(unsafe { dit::read() }, expected as u32);
            // A nested `Entry` leaves DIT to the outer one.
            drop(crate::low::Entry::new_secret());
            // SAFETY: as above.
            assert_eq!(unsafe { dit::read() }, expected as u32);
            drop(outer);
            // SAFETY: as above.
            assert_eq!(unsafe { dit::read() }, 0);
        }
    }

    #[test]
    fn dit_hold_keeps_dit_on_across_calls() {
        if features() & DIT == 0 {
            // Nothing to hold, and nothing to read DIT with.
            drop(crate::cpu::Dit::hold());
            return;
        }
        // SAFETY: this core has DIT. Cleared, so only the guard can set it.
        unsafe { dit::write(0) };
        let first = crate::cpu::Dit::hold();
        // A call under the guard, and a nested guard, leave DIT to it.
        drop(crate::low::Entry::new_secret());
        drop(crate::cpu::Dit::hold());
        // SAFETY: as above.
        assert_eq!(unsafe { dit::read() }, 1);
        // Guards may drop out of order: DIT waits for the last.
        let second = crate::cpu::Dit::hold();
        drop(first);
        // SAFETY: as above.
        assert_eq!(unsafe { dit::read() }, 1);
        drop(second);
        // SAFETY: as above.
        assert_eq!(unsafe { dit::read() }, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn needs_dit_on_every_possible_core() {
        use linux::all_cores_have_dit;
        // Neoverse N2 r0p0, as on Cobalt 100, and r3p1; Neoverse N1.
        let n2 = |_| Some(0x410f_d490);
        assert_eq!(all_cores_have_dit("0-3\n", n2), Some(true));
        assert_eq!(
            all_cores_have_dit("0,2-3", |_| Some(0x413f_d491)),
            Some(true)
        );
        let cpu2_n1 = |cpu| Some(if cpu == 2 { 0x413f_d0c1 } else { 0x410f_d490 });
        assert_eq!(all_cores_have_dit("0-3", cpu2_n1), Some(false));
        // Another implementer's part number.
        assert_eq!(all_cores_have_dit("0", |_| Some(0x510f_d490)), Some(false));
        // An offline core has no MIDR to read.
        let offline = |cpu| (cpu < 4).then_some(0x410f_d490);
        assert_eq!(all_cores_have_dit("0-3,8-11", offline), None);
        for malformed in ["", "\n", "3-0", "0-", "-3", "0,,1", "0-3-5", "a"] {
            assert_eq!(all_cores_have_dit(malformed, n2), None, "{malformed:?}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn child_reads_dit() -> bool {
        let test = concat!(module_path!(), "::reads_dit");
        let test = test.split_once("::").unwrap().1;
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture"])
            .env("RIND_TEST_READ_DIT", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() {
            assert!(stdout.contains("read DIT"), "{test} did not run:\n{stdout}");
            return true;
        }
        #[cfg(windows)]
        let illegal = out.status.code() == Some(0xc000_001d_u32 as i32);
        #[cfg(unix)]
        let illegal = std::os::unix::process::ExitStatusExt::signal(&out.status) == Some(4);
        assert!(illegal, "{test} failed with {}:\n{stdout}", out.status);
        false
    }

    /// Runs `mrs DIT` for `child_reads_dit`, which an illegal instruction
    /// kills on a core without DIT.
    #[test]
    fn reads_dit() {
        if std::env::var_os("RIND_TEST_READ_DIT").is_some() {
            let pstate: u64;
            // SAFETY: on a core without DIT this raises an illegal
            // instruction, which is the answer the parent wants.
            unsafe { core::arch::asm!("mrs {}, S3_3_C4_C2_5", out(reg) pstate) };
            println!("read DIT: {pstate:#x}");
        }
    }

    // The probe's illegal-instruction path is the one every core without DIT
    // takes, and CI's Windows runner has DIT, so `udf` stands in for it.
    #[cfg(windows)]
    #[test]
    fn probe_resumes_after_an_illegal_instruction() {
        let ran = |illegal: bool| {
            windows::probe(|| {
                let ran: u64;
                // SAFETY: `udf` raises the illegal instruction the probe
                // resumes past.
                unsafe {
                    if illegal {
                        core::arch::asm!("udf #0", "mov x0, #1", out("x0") ran, options(nostack));
                    } else {
                        core::arch::asm!("nop", "mov x0, #1", out("x0") ran, options(nostack));
                    }
                }
                ran
            })
        };
        assert!(!ran(true));
        assert!(ran(false));
    }
}
