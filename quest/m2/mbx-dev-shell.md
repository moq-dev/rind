# [S] rind's dev shell builds through the shared compile cache

## Goal

Cargo inside rind's Nix dev shell compiles through mbx, the compile cache the maintainer's hosts share across checkouts, so a new worktree reuses compiled work instead of building its own `target/` from scratch. Hosts without mbx behave as today, apart from the build-cost fixtures and `patch/fixture`, which now build in their own `target/`.

## Plan

Found on 2026-11-12 while measuring agent build times on fedora, nixos, and desktop:

- The hosts put mbx's cargo shim in `~/.local/share/mbx/bin`, but `nix develop` puts the flake's cargo ahead of it on `PATH`, so rind's builds bypass it (`mbx doctor`: "shim not active"). Outside the dev shell the shim fails with "could not find the real Cargo", seen 18 times in desktop's transcripts.
- fedora holds 40 `target/` folders across 57 worktrees, 179 GB in total (median 4.2 GB); a cold `just check` costs 15 s to 2.5 min more than a warm one.
- flake.nix's `mbx-shim` `shellHook` now puts the shim first in the `default`, `msrv`, `dart`, `ct-vartime`, `armv7` and `ct-qemu` (which extends `armv7`) shells and every `qemu-shell` one, on any host with a shim, and `sh/dispatch.sh`'s fixtures and `sh/patch.sh` dropped their `--target-dir target`. What remains here: the shells without the hook (`dudect`, `timing`, `coverage`, `prove`, `ctgrind`, `wasm`, `miri`, `regenerate`, `binsec`, `ct-qemu-aarch64`, `sde`, `hol-light`), and the shim's "could not find the real Cargo" case outside the dev shell, fixed upstream if it is mbx's to fix.
- Measure a cold `just check` in a fresh worktree before and after, and check `mbx stats` shows hits.
