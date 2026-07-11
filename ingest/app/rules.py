"""
rules.py — AUTO-GENERATED from config/*_rules.xml. DO NOT EDIT BY HAND.

Regenerate with:  python scripts/gen_rules.py

Single source of truth for rule_id -> (severity level, MITRE technique,
MITRE tactic). detect.py looks these up instead of hard-coding them, so the
local pipeline and the Wazuh manager stay in lock-step.
"""
from __future__ import annotations

RULES: dict[int, dict] = {
    100100: {"level": 0, "mitre": '', "tactic": ''},
    100101: {"level": 5, "mitre": 'T1110', "tactic": 'TA0006'},
    100102: {"level": 7, "mitre": 'T1078', "tactic": 'TA0001'},
    100103: {"level": 8, "mitre": 'T1059', "tactic": 'TA0002'},
    100104: {"level": 10, "mitre": 'T1105', "tactic": 'TA0011'},
    100105: {"level": 12, "mitre": 'T1105', "tactic": 'TA0011'},
    100106: {"level": 12, "mitre": 'T1572', "tactic": 'TA0011'},
    100107: {"level": 8, "mitre": 'T1110', "tactic": 'TA0006'},
    100108: {"level": 6, "mitre": 'T1110', "tactic": 'TA0006'},
    100109: {"level": 3, "mitre": '', "tactic": ''},
    100110: {"level": 10, "mitre": 'T1078', "tactic": 'TA0001'},
    100111: {"level": 7, "mitre": 'T1078', "tactic": 'TA0001'},
    100112: {"level": 6, "mitre": 'T1046', "tactic": 'TA0007'},
    100150: {"level": 10, "mitre": 'T1078', "tactic": 'TA0001'},
    100200: {"level": 0, "mitre": '', "tactic": ''},
    100201: {"level": 5, "mitre": 'T1046', "tactic": 'TA0007'},
    100202: {"level": 8, "mitre": 'T1210', "tactic": 'TA0008'},
    100203: {"level": 6, "mitre": 'T1046', "tactic": 'TA0007'},
    100204: {"level": 4, "mitre": '', "tactic": ''},
    100205: {"level": 12, "mitre": 'T1204', "tactic": 'TA0002'},
    100206: {"level": 6, "mitre": 'T1046', "tactic": 'TA0007'},
    100207: {"level": 6, "mitre": 'T1046', "tactic": 'TA0007'},
    100208: {"level": 10, "mitre": 'T1210', "tactic": 'TA0008'},
    100209: {"level": 7, "mitre": 'T1046', "tactic": 'TA0007'},
    100210: {"level": 8, "mitre": 'T1046', "tactic": 'TA0007'},
    100211: {"level": 9, "mitre": 'T1105', "tactic": 'TA0011'},
    100212: {"level": 5, "mitre": '', "tactic": ''},
    100213: {"level": 7, "mitre": 'T1046', "tactic": 'TA0007'},
    100214: {"level": 11, "mitre": 'T1204', "tactic": 'TA0002'},
    100215: {"level": 8, "mitre": 'T1588', "tactic": 'TA0042'},
    100216: {"level": 6, "mitre": 'T1110', "tactic": 'TA0006'},
    100217: {"level": 8, "mitre": 'T1110', "tactic": 'TA0006'},
    100300: {"level": 0, "mitre": '', "tactic": ''},
    100301: {"level": 3, "mitre": 'T1595', "tactic": 'TA0043'},
    100302: {"level": 6, "mitre": 'T1595', "tactic": 'TA0043'},
    100303: {"level": 7, "mitre": 'T1110', "tactic": 'TA0006'},
    100304: {"level": 7, "mitre": 'T1595', "tactic": 'TA0043'},
    100305: {"level": 10, "mitre": 'T1190', "tactic": 'TA0001'},
    100306: {"level": 8, "mitre": 'T1595', "tactic": 'TA0043'},
}
