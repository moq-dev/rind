# [S] x86-cpu runs one CPU model per dispatch path

## Goal

The nightly x86-cpu workflow covers the same dispatch paths in about 40
minutes instead of 90, by running one SDE CPU model per distinct set of
selected paths, plus both ends.

## Plan

Decided with the maintainer on 2026-11-01, from the merge-gate and CI audit:
m2 ✅ / m1 / m3.

- Map each of the 30 SDE models to the set of dispatch paths it selects.
  For example, Alder, Raptor, Meteor, Arrow, Lunar, and Panther Lake select
  the same paths, as does the Skylake-server family.
- Keep one model per set, plus Prescott, Diamond Rapids, and GNR256, and
  record the mapping in the workflow.
