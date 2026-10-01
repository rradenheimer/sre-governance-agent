"""Command-line interface for the SRE Governance Agent.

Usage (from repo root, with src on the path):
    python -m sre_governance.cli scan --repo . --profile commercial
    python -m sre_governance.cli validate-config
    python -m sre_governance.cli list-controls
    python -m sre_governance.cli verify-audit --audit .sre/audit.jsonl

The CLI is the single entry point used by BOTH agent variants (Copilot & Claude)
and the CI pipelines, guaranteeing identical, reproducible results everywhere.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sre_governance import __version__
from sre_governance.audit import AuditLogger
from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import CHECKS, evaluate
from sre_governance.report import render_json, render_markdown, render_sarif
from sre_governance.scanner import scan_repo

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = REPO_ROOT / "config" / "control-catalog.yaml"
DEFAULT_PROFILES = REPO_ROOT / "config" / "industry-profiles"


def _load(catalog_path: Path, profiles_dir: Path):
    catalog = load_catalog(catalog_path)
    profiles = load_profiles(profiles_dir)
    return catalog, profiles


def cmd_scan(args: argparse.Namespace) -> int:
    catalog, profiles = _load(Path(args.catalog), Path(args.profiles_dir))
    if args.profile not in profiles:
        print(f"ERROR: unknown profile '{args.profile}'. Available: {', '.join(profiles)}", file=sys.stderr)
        return 2
    profile = profiles[args.profile]

    audit = AuditLogger(args.audit, actor=args.actor)
    audit.record("scan_start", target=args.repo, profile=args.profile)

    scan = scan_repo(args.repo)
    assessment = evaluate(scan, catalog, profile)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    fmt = args.format

    if fmt in ("md", "all"):
        (out_dir / "sre-governance-report.md").write_text(
            render_markdown(assessment, profile.display_name, catalog.version), encoding="utf-8")
    if fmt in ("json", "all"):
        (out_dir / "sre-governance-report.json").write_text(
            render_json(assessment, catalog.version), encoding="utf-8")
    if fmt in ("sarif", "all"):
        (out_dir / "sre-governance.sarif").write_text(render_sarif(assessment), encoding="utf-8")

    audit.record(
        "scan_complete", target=args.repo,
        outcome="success" if assessment.gate.compliant else "non_compliant",
        score=assessment.score, gate_compliant=assessment.gate.compliant,
        blocking_failures=assessment.summary["blocking_failures"],
    )

    print(f"Profile:          {profile.display_name} ({profile.profile})")
    print(f"Compliance score: {assessment.score}%")
    print(f"Gate:             {'COMPLIANT' if assessment.gate.compliant else 'NON-COMPLIANT'} "
          f"[{profile.enforcement}]")
    for r in assessment.gate.reasons:
        print(f"  - {r}")
    print(f"Reports written to: {out_dir}")

    if assessment.gate.should_fail_pipeline:
        print("Policy gate failed under BLOCKING enforcement.", file=sys.stderr)
        return 1
    return 0


def cmd_validate_config(args: argparse.Namespace) -> int:
    catalog, profiles = _load(Path(args.catalog), Path(args.profiles_dir))
    errors: list[str] = []

    for control in catalog:
        ctype = control.check.get("type")
        if ctype not in CHECKS:
            errors.append(f"{control.id}: unknown check type '{ctype}'")

    all_ids = {c.id for c in catalog}
    for pname, profile in profiles.items():
        for cid in profile.control_overrides:
            if cid not in all_ids:
                errors.append(f"profile '{pname}' references unknown control '{cid}'")

    if errors:
        print("CONFIG VALIDATION FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: catalog v{catalog.version} with {len(all_ids)} controls; "
          f"profiles: {', '.join(profiles)}")
    return 0


def cmd_list_controls(args: argparse.Namespace) -> int:
    catalog, _ = _load(Path(args.catalog), Path(args.profiles_dir))
    for c in catalog:
        print(f"{c.id:<18} [{c.severity:<8}] {c.category:<14} {c.title}")
    return 0


def cmd_crosswalk(args: argparse.Namespace) -> int:
    catalog, _ = _load(Path(args.catalog), Path(args.profiles_dir))
    framework_map: dict[str, list[tuple[str, str]]] = {}
    for c in catalog:
        for fw, ids in c.mappings.items():
            framework_map.setdefault(fw, []).append((c.id, ", ".join(ids)))

    lines = ["# Framework Crosswalk",
             "",
             "Generated from `config/control-catalog.yaml`. Maps each compliance "
             "framework to the SRE Governance controls that satisfy it.",
             ""]
    for fw in sorted(framework_map):
        lines.append(f"## {fw}")
        lines.append("")
        lines.append("| Control | Framework reference(s) |")
        lines.append("|---|---|")
        for cid, refs in sorted(framework_map[fw]):
            lines.append(f"| `{cid}` | {refs} |")
        lines.append("")
    out = "\n".join(lines)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote crosswalk to {args.out}")
    else:
        print(out)
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    ok, msg = AuditLogger(args.audit).verify()
    print(("OK: " if ok else "FAILED: ") + msg)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sre-governance-agent", description="SRE Governance Agent CLI")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--catalog", default=str(DEFAULT_CATALOG))
        sp.add_argument("--profiles-dir", default=str(DEFAULT_PROFILES))

    sp = sub.add_parser("scan", help="Scan a repo and emit reports")
    add_common(sp)
    sp.add_argument("--repo", default=".")
    sp.add_argument("--profile", required=True)
    sp.add_argument("--format", choices=["md", "json", "sarif", "all"], default="all")
    sp.add_argument("--out", default="sre-reports")
    sp.add_argument("--audit", default=".sre/audit.jsonl")
    sp.add_argument("--actor", default="sre-governance-agent")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("validate-config", help="Validate catalog + profiles")
    add_common(sp)
    sp.set_defaults(func=cmd_validate_config)

    sp = sub.add_parser("list-controls", help="List all controls")
    add_common(sp)
    sp.set_defaults(func=cmd_list_controls)

    sp = sub.add_parser("verify-audit", help="Verify the audit hash chain")
    sp.add_argument("--audit", default=".sre/audit.jsonl")
    sp.set_defaults(func=cmd_verify_audit)

    sp = sub.add_parser("crosswalk", help="Emit a framework->controls crosswalk (Markdown)")
    add_common(sp)
    sp.add_argument("--out", default="")
    sp.set_defaults(func=cmd_crosswalk)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
