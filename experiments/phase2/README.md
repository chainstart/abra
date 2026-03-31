# Phase-2 Fork Replay Workspace

This directory is the execution workspace for attack replay and sandbox experiments.

## Current scope

- Batch-1 shortlist: `data/processed/phase2_batch1_incidents.csv`
- Batch-1 report: `reports/19_phase2_batch1_incident_shortlist.md`
- Event cards: `reports/events/`

## Workflow

1. Pick one incident from the batch shortlist.
2. Fill the corresponding event card with:
   - root cause hypothesis
   - exact addresses
   - chosen fork block
   - exploit steps
   - assertions
3. Implement a dedicated Foundry test in `test/replay/`.
4. Capture results in a report under `reports/`.

## Conventions

- One replay test contract per incident family or protocol.
- Fixed fork block for reproducibility.
- Explicit profit / collateral / state assertions.
- Record mitigations next to exploit assumptions.

