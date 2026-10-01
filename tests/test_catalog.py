from pathlib import Path

from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import CHECKS

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "control-catalog.yaml"
PROFILES = ROOT / "config" / "industry-profiles"


def test_catalog_loads_and_ids_unique():
    catalog = load_catalog(CATALOG)
    ids = [c.id for c in catalog]
    assert len(ids) == len(set(ids)), "duplicate control ids"
    assert len(ids) >= 20


def test_every_check_type_is_registered():
    catalog = load_catalog(CATALOG)
    for control in catalog:
        assert control.check["type"] in CHECKS, f"{control.id} uses unknown check"


def test_every_control_has_mappings_and_remediation():
    catalog = load_catalog(CATALOG)
    for control in catalog:
        assert control.remediation, f"{control.id} missing remediation"
        assert control.severity in {"critical", "high", "medium", "low"}


def test_profiles_load_and_reference_known_controls():
    catalog = load_catalog(CATALOG)
    known = {c.id for c in catalog}
    profiles = load_profiles(PROFILES)
    assert {"federal-defense", "regulated", "commercial"} <= set(profiles)
    for profile in profiles.values():
        for cid in profile.control_overrides:
            assert cid in known, f"{profile.profile} references unknown {cid}"


def test_federal_is_strictest():
    profiles = load_profiles(PROFILES)
    fed = profiles["federal-defense"]
    com = profiles["commercial"]
    assert fed.thresholds["min_compliance_score"] > com.thresholds["min_compliance_score"]
    assert fed.thresholds["required_reviewers"] >= com.thresholds["required_reviewers"]
    assert fed.enforcement == "blocking"
