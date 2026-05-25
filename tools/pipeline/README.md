# Phase-1 Data Foundation Pipeline

This folder implements the first execution phase of the research plan:

1. Ingest incident data from `hacked.slowmist.io`
2. Ingest protocol/chain snapshots from `api.llama.fi`
3. Ingest direct evidence candidates from replay- and tx-oriented sources
4. Normalize data for downstream analysis and experiments
5. Generate a quality report for coverage, source mix, and onchain-anchor missingness checks

## Scripts

- `slowmist_collector.py`: paginated incident collector
- `defillama_collector.py`: protocol/chain snapshot collector
- `direct_evidence_collector.py`: direct tx / replay candidate collector
- `normalize.py`: schema normalization and heuristic labeling
- `data_quality_report.py`: markdown quality report
- `generate_event_cards.py`: per-incident replay card generator
- `select_phase2_incidents.py`: shortlist builder for fork replay batches
- `run_phase1.py`: one-command pipeline runner

## Quick Start

From repository root:

```bash
pip install -r tools/requirements.txt

# Small validation run (first 3 pages)
python3 tools/pipeline/run_phase1.py --start-page 1 --end-page 3 --top-protocols 200

# Full crawl can be done by expanding the page range
python3 tools/pipeline/run_phase1.py --start-page 1 --end-page 102 --top-protocols 800 --save-html

# Direct evidence only
python3 tools/pipeline/direct_evidence_collector.py --max-defihacklabs 250

# Generate replay cards for top DeFi incidents by loss
python3 tools/pipeline/generate_event_cards.py --top-n 50

# Select a high-priority replay batch and generate its cards
python3 tools/pipeline/select_phase2_incidents.py
python3 tools/pipeline/generate_event_cards.py \
  --selected-incidents-csv data/processed/phase2_batch1_incidents.csv \
  --output-dir reports/events \
  --top-n 12
```

For larger DeFiHackLabs refreshes, provide `GITHUB_PERSONAL_ACCESS_TOKEN`, `GITHUB_TOKEN`,
or `GH_TOKEN` in the process environment or `.env.local`. The direct evidence collector also
falls back to existing local `git` GitHub credentials when available, and if GitHub rate limits
still fire mid-run it preserves the partial candidate set instead of aborting the whole Phase-1 step.

## Output Paths

- Raw incident snapshots: `data/raw/slowmist/`
- Raw protocol snapshots: `data/raw/defillama/`
- Raw direct evidence snapshots: `data/raw/direct_evidence/`
- Normalized tables: `data/processed/`
- Data quality report: `reports/17_phase1_data_quality.md`
- Incident replay cards: `reports/events/`

## Normalized Incident Schema

- `incident_id`: deterministic hash ID
- `event_date`: date on SlowMist page
- `target`: hacked target label
- `protocol_slug_guess`: best-effort DefiLlama slug match
- `is_defi`: heuristic flag (`true` / `false`)
- `attack_method_raw`: raw attack method from source
- `attack_family`: normalized method family
- `loss_usd_raw`: raw loss text
- `loss_usd`: parsed numeric loss (USD)
- `reference_url`: source link
- `source_url`, `source_page`, `category_filter`: provenance fields
- `seed_transaction_hash`, `fork_block`: direct onchain anchor fields preserved from direct evidence sources
- `description`: event description
