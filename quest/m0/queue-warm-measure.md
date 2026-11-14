# [XS] Measure the merge queue's writes once it builds through mbx

## Goal

A day of rind's merge queue building through mbx shows how far the rind-ci runner's disk writes per job fell from the baseline, recorded on [kixel-ai/rind#740](https://github.com/kixel-ai/rind/pull/740), the PR that switched it.

## Plan

- Baselines on nixos's `container@rind-ci` unit: 155.5 GB written over about 27 queue jobs in the 14 hours before 2026-11-13 13:09 PST (about 5.7 GB a job, from its `Consumed ... written to disk` journal line), and, after the container restarted with dotfiles#135's `CARGO_INCREMENTAL=0` (in the runner's environment by 15:30), 35.2 GB over about 10.5 jobs from 13:09:54 to 15:30 PST (about 3.3 GB a job, from `systemctl show container@rind-ci -p IOWriteBytes`).
- `queue-build.yml` runs main's copy, so the first group after #740 lands is the first to build through mbx; its first job also drops the runner's managed targets once (the version stamp) and fills the store, so start the window after it.
- Over a window of at least a day, read `IOWriteBytes` at both ends and take the difference (if the container restarted in between: the first instance's journal total minus the start reading, plus each later stopped instance's journal total, plus the end reading), and divide by the merge-group runs of `queue.yml` in it (`gh api -X GET repos/kixel-ai/rind/actions/workflows/queue.yml/runs -f event=merge_group -f created=...`). Note the result on #740. If writes did not fall well below the second baseline, find which builds still write (for example `biotop` or the managed targets' growth) and fix them here.

## Scheduled

- 2026-11-15 - a full day after the switch can land
