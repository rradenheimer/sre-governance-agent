"""Loading and modelling the control catalog and industry profiles."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"mandatory", "recommended", "not_applicable"}
VALID_AUTONOMY = {"suggest_only", "propose_pr", "never"}


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    category: str
    severity: str
    automatable: bool
    description: str
    rationale: str
    check: dict[str, Any]
    remediation: str
    mappings: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Catalog:
    version: str
    controls: dict[str, Control]

    def __iter__(self):
        return iter(self.controls.values())

    def get(self, control_id: str) -> Control:
        return self.controls[control_id]


@dataclass(frozen=True)
class Profile:
    profile: str
    display_name: str
    description: str
    baseline: str
    enforcement: str                 # blocking | warning
    ai_autonomy: str                 # suggest_only | propose_pr | never
    require_human_approval: bool
    frameworks: list[str]
    thresholds: dict[str, Any]
    default_status: str
    control_overrides: dict[str, str]
    data_handling: dict[str, Any]

    def status_for(self, control_id: str) -> str:
        return self.control_overrides.get(control_id, self.default_status)


def load_catalog(path: str | Path) -> Catalog:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    controls: dict[str, Control] = {}
    for item in raw.get("controls", []):
        _validate_control(item)
        control = Control(
            id=item["id"],
            title=item["title"],
            category=item["category"],
            severity=item["severity"],
            automatable=bool(item.get("automatable", False)),
            description=item.get("description", "").strip(),
            rationale=item.get("rationale", "").strip(),
            check=item["check"],
            remediation=item.get("remediation", "").strip(),
            mappings=item.get("mappings", {}) or {},
        )
        if control.id in controls:
            raise ValueError(f"Duplicate control id: {control.id}")
        controls[control.id] = control
    return Catalog(version=str(raw.get("version", "0")), controls=controls)


def load_profile(path: str | Path) -> Profile:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    overrides = {
        k: v for k, v in (raw.get("controls", {}) or {}).items()
    }
    for cid, status in overrides.items():
        if status not in VALID_STATUSES:
            raise ValueError(f"Profile {raw.get('profile')} control {cid} has invalid status '{status}'")
    default_status = raw.get("default_status", "recommended")
    if default_status not in VALID_STATUSES:
        raise ValueError(f"Invalid default_status '{default_status}' in {path}")
    enforcement = raw.get("enforcement", "warning")
    if enforcement not in {"blocking", "warning"}:
        raise ValueError(f"Invalid enforcement '{enforcement}' in {path}")
    ai_autonomy = raw.get("ai_autonomy", "suggest_only")
    if not isinstance(ai_autonomy, str) or ai_autonomy not in VALID_AUTONOMY:
        raise ValueError(f"Invalid ai_autonomy '{ai_autonomy}' in {path}")
    require_human_approval = raw.get("require_human_approval", True)
    if not isinstance(require_human_approval, bool):
        raise ValueError(f"require_human_approval must be a boolean in {path}")
    return Profile(
        profile=raw["profile"],
        display_name=raw.get("display_name", raw["profile"]),
        description=raw.get("description", "").strip(),
        baseline=raw.get("baseline", "standard"),
        enforcement=enforcement,
        ai_autonomy=ai_autonomy,
        require_human_approval=require_human_approval,
        frameworks=list(raw.get("frameworks", [])),
        thresholds=raw.get("thresholds", {}) or {},
        default_status=default_status,
        control_overrides=overrides,
        data_handling=raw.get("data_handling", {}) or {},
    )


def load_profiles(directory: str | Path) -> dict[str, Profile]:
    directory = Path(directory)
    profiles: dict[str, Profile] = {}
    for p in sorted(directory.glob("*.yaml")):
        profile = load_profile(p)
        profiles[profile.profile] = profile
    return profiles


def _validate_control(item: dict[str, Any]) -> None:
    for required in ("id", "title", "category", "severity", "check"):
        if required not in item:
            raise ValueError(f"Control missing required field '{required}': {item.get('id', item)}")
    if item["severity"] not in VALID_SEVERITIES:
        raise ValueError(f"Control {item['id']} has invalid severity '{item['severity']}'")
    if "type" not in item["check"]:
        raise ValueError(f"Control {item['id']} check missing 'type'")
