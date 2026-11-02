# [XS] armv7 debug ctgrind, end of m2

## Goal

armv7 ctgrind passes on debug builds at the end of each milestone, since no
nightly job runs it. This run checks the end of m2.

## Plan

Decided with the maintainer on 2026-11-02: recur at the end of each
milestone ✅ / once at the end of m2 / per minor release. #208 confirmed it
passing on 2026-11-02 (run 41349429240).

- Recurring. This run lives in m3 and requires m2, so it is ready once m2's
  work is done. The PR that finishes it deletes this file and creates the
  next run at `/quest/m4/armv7-debug-ct.md` (creating m4 if needed), with
  `Required` linking `/quest/m3/README.md`, linked from m4's `Required`, and
  this Plan carried forward with the latest run's result.
- Run it from a throwaway branch whose `ctgrind.yml` drops `--release` from
  the armv7 jobs and adds `--no-fail-fast`, as #208 did; delete the branch
  after reading the run.
- Fix what it reports: rind's secret arithmetic wraps, and dependencies'
  debug checks are turned off in the workspace dev profile. Findings that
  need their own work are follow-ups for `/quest-plan`.

## Required

- [m2: later work](/quest/m2/README.md) - this run checks the end of m2
