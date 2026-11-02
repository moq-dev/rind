# [XS] admin/structure without graphviz

## Goal

`admin/structure` filters cargo-modules' output without graphviz's `gvpr`, so
the default dev shell drops `graphviz` (up to 143 MiB per CI job), with the
same errors reported.

## Plan

- `admin/structure` pipes `cargo modules dependencies` through a `gvpr`
  script. Do the same filtering with awk (or another tool already in the
  shell) over the DOT text.
- Remove `graphviz` from `flake.nix`'s default shell.
- Compare the report before and after on main and on a planted violation.
