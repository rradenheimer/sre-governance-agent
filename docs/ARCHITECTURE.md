# Architecture

## Design principle: separate judgment from language

The system splits cleanly into two layers:

1. **Deterministic policy engine** (`src/sre_governance/`) — pure Python, no AI,
   no network, no randomness. Given a repo, a catalog, and a profile, it always
   produces the same results. This is what auditors and pipelines trust.
2. **AI orchestration layer** (`agents/copilot/`, `agents/claude/`) — uses an LLM
   to *interpret* findings, *explain* them against frameworks, and *draft*
   minimal remediations. It is bounded by profile autonomy, hooks, and reviews.

Both agent editions call the **same CLI**, so Copilot, Claude, and CI always
agree.

## Components

```
config/control-catalog.yaml      21 controls, severities, checks, framework maps
config/industry-profiles/*.yaml  which controls are mandatory + thresholds
        │
        ▼
src/sre_governance/
  catalog.py   load + validate catalog and profiles (dataclasses)
  scanner.py   read-only repo signal collection (files, workflows, metadata)
  engine.py    CHECKS registry + evaluate() → Results + score + Gate
  report.py    render Markdown / JSON / SARIF
  audit.py     hash-chained audit log + provenance
  cli.py       scan | validate-config | list-controls | verify-audit | crosswalk
```

## Evaluation model

- The **scanner** collects deterministic *signals*: the set of file/dir paths,
  concatenated CI-workflow text, and declared `.sre/governance.yaml` metadata.
  The bundled CI workflow does not query the GitHub API. The
  `merge_api_metadata` helper supports callers supplying separately verified
  values, but the CLI scan uses declarations as attestations.
- Each control declares a **check** evaluated by a named function in
  `engine.CHECKS`: `file_exists`, `file_absent`, `workflow_present`,
  `content_match`, `metadata_true`, `metadata_all_true`, `audit_log_valid`,
  `metadata_gte`, `metadata_in`.
- A **profile** maps each control to `mandatory` / `recommended` /
  `not_applicable` and sets thresholds (reviewers, min score, failure budgets).
- **Scoring** is severity-weighted (critical 10, high 6, medium 3, low 1) over
  applicable controls; NA controls are excluded.
- The **gate** fails when mandatory CRITICAL/HIGH budgets or the minimum score
  are breached. `enforcement: blocking` turns a failed gate into a non-zero exit
  (fails CI); `warning` reports but does not block.

## Extensibility

- **Add a control:** append to `config/control-catalog.yaml` with a `check` of a
  supported type and framework mappings. `validate-config` enforces integrity.
- **Add a check type:** register a function in `engine.CHECKS`.
- **Add a profile/industry:** drop a new YAML in `config/industry-profiles/`.
- **Add a report format:** add a renderer in `report.py`.

Everything is covered by tests in `tests/`.
