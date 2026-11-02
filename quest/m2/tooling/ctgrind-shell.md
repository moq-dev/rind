# [XS] A ctgrind dev shell

## Goal

`admin/ctgrind` runs locally from a dedicated dev shell without setting
`LIBCLANG_PATH` by hand, and the ctgrind workflow uses the same shell.

## Plan

Decided with the maintainer on 2026-11-02: a `devShells.ctgrind` ✅ / add
libclang to the default shell.

- ctgrind's bindgen needs libclang, which the default shell lacks (#204 had
  to point `LIBCLANG_PATH` at nixpkgs' `llvmPackages.libclang.lib`).
- Add `devShells.ctgrind` with libclang and valgrind, set `LIBCLANG_PATH`
  there, and run `admin/ctgrind` and `ctgrind.yml` through it. Keep the
  default shell unchanged.
