from driver import (
    Architecture_aarch64,
    Architecture_amd64,
    RustDriver,
)
from parse import parse_file


def emit(arch, source_dir, out_dir, source, name, rust_decl, parameters, hoist=None):
    with (
        open(f"../../thirdparty/s2n-bignum/{source_dir}/p521/{source}.S") as input,
        open(f"../../rind/src/low/{out_dir}/{name}.rs", "w") as output,
    ):
        d = RustDriver(output, arch)
        d.emit_rust_function(
            source,
            parameter_map=[("inout", p) for p in parameters],
            rust_decl=rust_decl,
            hoist=hoist,
        )
        parse_file(input, d)


LOCAL_FUNCTIONS = {
    "p521_jadd": "sub_p521",
    "p521_jmixadd": "sub_p521",
    "p521_jdouble": "sqr_p521",
}


def emit_all(arch, source_dir, out_dir, alt):
    zx = ["z.as_mut_ptr() => _", "x.as_ptr() => _"]
    zxy = zx + ["y.as_ptr() => _"]
    p3p1p2 = ["p3.as_mut_ptr() => _", "p1.as_ptr() => _", "p2.as_ptr() => _"]

    for source, name, rust_decl, parameters in [
        (
            "bignum_mul_p521" + alt,
            "bignum_mul_p521",
            "fn bignum_mul_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9])",
            zxy,
        ),
        (
            "bignum_sqr_p521" + alt,
            "bignum_sqr_p521",
            "fn bignum_sqr_p521(z: &mut [u64; 9], x: &[u64; 9])",
            zx,
        ),
        (
            "bignum_add_p521",
            "bignum_add_p521",
            "fn bignum_add_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9])",
            zxy,
        ),
        (
            "bignum_neg_p521",
            "bignum_neg_p521",
            "fn bignum_neg_p521(z: &mut [u64; 9], x: &[u64; 9])",
            zx,
        ),
        (
            "bignum_inv_p521",
            "bignum_inv_p521",
            "fn bignum_inv_p521(z: &mut [u64; 9], x: &[u64; 9])",
            zx,
        ),
        (
            "bignum_mod_n521_9",
            "bignum_mod_n521",
            "fn bignum_mod_n521(z: &mut [u64; 9], x: &[u64; 9])",
            zx,
        ),
        (
            "p521_jadd" + alt,
            "p521_jadd",
            "fn p521_jadd(p3: &mut [u64; 27], p1: &[u64; 27], p2: &[u64; 27])",
            p3p1p2,
        ),
        (
            "p521_jmixadd" + alt,
            "p521_jmixadd",
            "fn p521_jmixadd(p3: &mut [u64; 27], p1: &[u64; 27], p2: &[u64; 18])",
            p3p1p2,
        ),
        (
            "p521_jdouble" + alt,
            "p521_jdouble",
            "fn p521_jdouble(p3: &mut [u64; 27], p1: &[u64; 27])",
            p3p1p2[:2],
        ),
    ]:
        # aarch64's point routines without `_alt` call local functions after
        # their body; the last of them ends the hoist.
        hoist = None
        if source_dir == "arm" and source in LOCAL_FUNCTIONS:
            hoist = ["proc", f"L{source}_local_{LOCAL_FUNCTIONS[source]}", "ret"]
        emit(arch, source_dir, out_dir, source, name, rust_decl, parameters, hoist)

    # Its local functions follow its body; the last of them ends the hoist.
    last = "sqr_p521" if source_dir == "x86" else "sub_p521"
    emit(
        arch,
        source_dir,
        out_dir,
        "p521_jscalarmul" + alt,
        "p521_jscalarmul",
        "fn p521_jscalarmul(res: &mut [u64; 27], scalar: &[u64; 9], point: &[u64; 27])",
        ["res.as_mut_ptr() => _", "scalar.as_ptr() => _", "point.as_ptr() => _"],
        hoist=["proc", f"Lp521_jscalarmul{alt}_{last}", "ret"],
    )


if __name__ == "__main__":
    emit_all(Architecture_amd64, "x86", "x86_64", "")
    emit_all(Architecture_aarch64, "arm", "aarch64", "")
