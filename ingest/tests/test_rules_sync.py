"""
Guards the single-source-of-truth contract: the generated rule catalog
(app/rules.py) must stay in sync with the Wazuh XML in config/. If someone
edits a rule's level or MITRE mapping in the XML without regenerating (or edits
rules.py by hand), this test fails with a clear instruction.
"""
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "config"
GEN = REPO / "scripts" / "gen_rules.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_rules", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(not GEN.exists() or not CONFIG.exists(),
                    reason="run from a full checkout with config/ and scripts/")
def test_catalog_matches_xml():
    gen = _load_generator()
    expected = gen.build_catalog(CONFIG)
    from app.rules import RULES
    assert RULES == expected, "app/rules.py is stale — run: python scripts/gen_rules.py"


@pytest.mark.skipif(not GEN.exists() or not CONFIG.exists(),
                    reason="run from a full checkout with config/ and scripts/")
def test_every_fired_rule_is_in_catalog():
    """Import detect.py and confirm every rule id it can emit exists in the
    catalog (a missing one would raise at runtime)."""
    from app import detect
    from app.rules import RULES
    fired = set()
    # rules referenced by the per-protocol connection + webtrap tables
    for rid, _desc in detect._DIO_CONN_RULES.values():
        fired.add(rid)
    for rid, _desc, _cat in detect._WEBTRAP_RULES.values():
        fired.add(rid)
    # the rest are constructed inline; assert the ones the tests exercise exist
    for rid in (100101, 100102, 100103, 100104, 100105, 100106, 100107, 100108,
                100111, 100112, 100150, 100205, 100208, 100210, 100211, 100214,
                100215, 100216, 100217, 100306):
        fired.add(rid)
    missing = fired - set(RULES)
    assert not missing, f"rules fired by detect.py but absent from catalog: {missing}"
