"""Loading, validating, and matching Sigma-like YAML detection rules.

Selection syntax (all fields must match; a list means "any of"):

    selection:
      event_action: ssh_login          # equals (case-insensitive)
      event_outcome: [failure]         # any of
      process|contains: [/etc/shadow]  # modifiers: contains, startswith,
      http_status|gte: 400             #   endswith, re, gte, lte
"""

import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

from .. import config
from ..models import EVENT_FIELDS

SEVERITIES = ("low", "medium", "high", "critical")
RULE_TYPES = ("match", "threshold", "sequence", "first_seen")
MODIFIERS = ("eq", "contains", "startswith", "endswith", "re", "gte", "lte")
_TIMEFRAME = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class RuleError(ValueError):
    pass


def parse_timeframe(value: str) -> timedelta:
    m = _TIMEFRAME.match(str(value).strip())
    if not m:
        raise RuleError(f"invalid timeframe {value!r} (use e.g. 30s, 5m, 1h, 1d)")
    return timedelta(**{_UNITS[m[2]]: int(m[1])})


@dataclass
class Condition:
    field: str
    modifier: str
    values: list

    def matches(self, event: dict) -> bool:
        actual = event.get(self.field)
        if actual is None:
            return False
        if self.modifier in ("gte", "lte"):
            try:
                num = float(actual)
            except (TypeError, ValueError):
                return False
            return any(num >= v if self.modifier == "gte" else num <= v for v in self.values)
        if self.modifier == "re":
            return any(v.search(str(actual)) for v in self.values)
        text = str(actual).lower()
        if self.modifier == "eq":
            return any(text == v for v in self.values)
        if self.modifier == "contains":
            return any(v in text for v in self.values)
        if self.modifier == "startswith":
            return any(text.startswith(v) for v in self.values)
        return any(text.endswith(v) for v in self.values)  # endswith


@dataclass
class Selection:
    conditions: list[Condition]

    def matches(self, event: dict) -> bool:
        return all(c.matches(event) for c in self.conditions)

    @classmethod
    def parse(cls, raw: dict, where: str) -> "Selection":
        if not isinstance(raw, dict) or not raw:
            raise RuleError(f"{where}: selection must be a non-empty mapping")
        conditions = []
        for key, value in raw.items():
            fname, _, modifier = str(key).partition("|")
            modifier = modifier or "eq"
            if fname not in EVENT_FIELDS:
                raise RuleError(f"{where}: unknown field {fname!r}")
            if modifier not in MODIFIERS:
                raise RuleError(f"{where}: unknown modifier {modifier!r}")
            values = value if isinstance(value, list) else [value]
            if not values:
                raise RuleError(f"{where}: {key} has no values")
            if modifier in ("gte", "lte"):
                values = [float(v) for v in values]
            elif modifier == "re":
                values = [re.compile(str(v), re.IGNORECASE) for v in values]
            else:
                values = [str(v).lower() for v in values]
            conditions.append(Condition(fname, modifier, values))
        return cls(conditions)


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    type: str
    logsource: dict
    summary: str
    attack_technique: str | None = None
    attack_name: str | None = None
    attack_tactics: list[str] = field(default_factory=list)
    enabled: bool = True
    selection: Selection | None = None
    group_by: list[str] = field(default_factory=list)
    threshold: int = 1
    timeframe: timedelta | None = None
    steps: list[tuple[Selection, int]] = field(default_factory=list)
    new_value_field: str | None = None
    path: str | None = None

    @property
    def source_type(self) -> str | None:
        return self.logsource.get("source_type")

    def to_public(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "type": self.type,
            "source_type": self.source_type,
            "attack_technique": self.attack_technique,
            "attack_name": self.attack_name,
            "attack_tactics": self.attack_tactics,
            "enabled": self.enabled,
            "group_by": self.group_by,
            "threshold": self.threshold if self.type in ("threshold", "sequence") else None,
            "timeframe_seconds": int(self.timeframe.total_seconds()) if self.timeframe else None,
        }


def _require(raw: dict, key: str, where: str):
    if key not in raw or raw[key] in (None, ""):
        raise RuleError(f"{where}: missing required key {key!r}")
    return raw[key]


def parse_rule(raw: dict, where: str = "<rule>") -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: rule must be a mapping")
    severity = str(_require(raw, "severity", where)).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {SEVERITIES}")
    detection = _require(raw, "detection", where)
    rtype = _require(detection, "type", where)
    if rtype not in RULE_TYPES:
        raise RuleError(f"{where}: detection.type must be one of {RULE_TYPES}")
    attack = raw.get("attack") or {}

    rule = Rule(
        id=str(_require(raw, "id", where)),
        title=str(_require(raw, "title", where)),
        description=str(raw.get("description", "")).strip(),
        severity=severity,
        type=rtype,
        logsource=raw.get("logsource") or {},
        summary=str(raw.get("summary") or raw["title"]),
        attack_technique=attack.get("technique"),
        attack_name=attack.get("name"),
        attack_tactics=list(attack.get("tactics") or []),
        enabled=bool(raw.get("enabled", True)),
        group_by=list(detection.get("group_by") or []),
        path=where,
    )
    for g in rule.group_by:
        if g not in EVENT_FIELDS:
            raise RuleError(f"{where}: unknown group_by field {g!r}")

    if rtype in ("match", "threshold", "first_seen"):
        rule.selection = Selection.parse(_require(detection, "selection", where), where)
    if rtype in ("threshold", "sequence"):
        rule.timeframe = parse_timeframe(_require(detection, "timeframe", where))
    if rtype == "threshold":
        rule.threshold = int(_require(detection, "threshold", where))
        if rule.threshold < 1:
            raise RuleError(f"{where}: threshold must be >= 1")
    if rtype == "sequence":
        steps = _require(detection, "steps", where)
        if not isinstance(steps, list) or len(steps) != 2:
            raise RuleError(f"{where}: sequence rules need exactly 2 steps")
        rule.steps = [
            (Selection.parse(s.get("selection"), where), int(s.get("min_count", 1))) for s in steps
        ]
        rule.threshold = rule.steps[0][1]
    if rtype == "first_seen":
        rule.new_value_field = _require(detection, "field", where)
        if rule.new_value_field not in EVENT_FIELDS:
            raise RuleError(f"{where}: unknown field {rule.new_value_field!r}")
        if not rule.group_by:
            raise RuleError(f"{where}: first_seen rules need group_by")
    return rule


def load_rules(directory: Path | None = None) -> list[Rule]:
    directory = Path(directory or config.rules_dir())
    rules, ids = [], set()
    for path in sorted(directory.glob("*.y*ml")):
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        rule = parse_rule(raw, where=path.name)
        if rule.id in ids:
            raise RuleError(f"{path.name}: duplicate rule id {rule.id!r}")
        ids.add(rule.id)
        rules.append(rule)
    return rules
