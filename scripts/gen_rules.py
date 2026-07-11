#!/usr/bin/env python3
"""
gen_rules.py — single-source the detection rule metadata.

The Wazuh rule files in config/ are the authoritative source for each rule's
severity level and MITRE ATT&CK mapping. Historically those numbers were also
hand-copied into app/detect.py, and the two drifted (e.g. a MITRE tactic that
disagreed). This script parses the XML and regenerates ingest/app/rules.py so
the Python pipeline and the Wazuh manager can never disagree on
  rule_id -> (level, MITRE technique, MITRE tactic).

Descriptions are intentionally NOT single-sourced: the XML carries French text
for SIEM analysts, while the dashboard shows English — those are per-surface UI
strings, not the machine contract.

Usage:
    python scripts/gen_rules.py          # regenerate ingest/app/rules.py
    python scripts/gen_rules.py --check   # exit 1 if the file is out of date
"""
from __future__ import annotations
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO / "config"
OUTPUT = REPO / "ingest" / "app" / "rules.py"


def build_catalog(config_dir: Path | str = CONFIG_DIR) -> dict[int, dict]:
    """Parse every <rule> in config/*.xml into {id: {level, mitre, tactic}}."""
    config_dir = Path(config_dir)
    catalog: dict[int, dict] = {}
    for xml_path in sorted(config_dir.glob("*_rules.xml")):
        root = ET.parse(xml_path).getroot()
        for rule in root.iter("rule"):
            rid = int(rule.attrib["id"])
            # support both the simplified <mitre_id> form used here and the
            # canonical Wazuh <mitre><id>…</id></mitre> nesting
            mitre = rule.findtext("mitre_id") or rule.findtext("mitre/id") or ""
            tactic = rule.findtext("mitre_tactic") or rule.findtext("mitre/tactic") or ""
            catalog[rid] = {
                "level": int(rule.attrib.get("level", 0)),
                "mitre": mitre.strip(),
                "tactic": tactic.strip(),
            }
    if not catalog:
        raise SystemExit(f"no rules found under {config_dir} — nothing to generate")
    return dict(sorted(catalog.items()))


def render(catalog: dict[int, dict]) -> str:
    lines = [
        '"""',
        "rules.py — AUTO-GENERATED from config/*_rules.xml. DO NOT EDIT BY HAND.",
        "",
        "Regenerate with:  python scripts/gen_rules.py",
        "",
        "Single source of truth for rule_id -> (severity level, MITRE technique,",
        "MITRE tactic). detect.py looks these up instead of hard-coding them, so the",
        "local pipeline and the Wazuh manager stay in lock-step.",
        '"""',
        "from __future__ import annotations",
        "",
        "RULES: dict[int, dict] = {",
    ]
    for rid, meta in catalog.items():
        lines.append(
            f'    {rid}: {{"level": {meta["level"]}, '
            f'"mitre": {meta["mitre"]!r}, "tactic": {meta["tactic"]!r}}},'
        )
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    catalog = build_catalog()
    generated = render(catalog)
    if "--check" in argv:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != generated:
            print("ingest/app/rules.py is out of date — run: python scripts/gen_rules.py",
                  file=sys.stderr)
            return 1
        print("rules.py is in sync with config/*.xml")
        return 0
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO)} ({len(catalog)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
