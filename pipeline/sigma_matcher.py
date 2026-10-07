"""
In-memory Sigma detection matcher.

This is the single genuinely non-trivial piece of engineering in the project
(see brief Section 6.6). It lets the CI test suite prove that a detection
*actually fires* on captured attack telemetry and *does not fire* on a clean
baseline -- WITHOUT needing a live SIEM running inside the GitHub Actions job.
The whole test suite therefore runs in seconds with `pyyaml` as the only
runtime dependency.

Design choices (all deliberate, all defensible in an interview):

* We evaluate a Sigma rule against a *list of already-normalized log events*
  (flat dicts). Fixtures under tests/fixtures/ are normalized to flat records
  whose keys match the Sigma field names (EventID, Image, CommandLine, ...).
  Real Sysmon/Windows Event Log JSON is nested; the normalization step that
  flattens it lives in the fixtures themselves and is documented in
  docs/architecture.md. Keeping the matcher's input flat keeps the matcher
  small and readable, which is the whole point of strategy 1 in the brief.

* String comparisons are case-insensitive by default, matching Sigma's own
  default semantics.

* Supported detection features: named selections (maps), list-of-maps
  selections (OR), scalar and list values (list => OR), field modifiers
  (contains / startswith / endswith / all / re / gt / gte / lt / lte / cased),
  `null` values, and condition expressions using and / or / not / parentheses,
  `1 of them` / `all of them`, and `1 of prefix*` / `all of prefix*`.

* Count aggregation is supported for the common shape
  `selection | count(field) by groupfield >= N` (and the `count()` event-count
  form). Time-window (`timeframe`) correlation and "failed-then-success"
  sequence correlation are intentionally NOT modelled here; they belong to the
  SIEM/correlation layer or to Sigma's newer correlation-rule spec, and that
  limitation is stated honestly in the rule comments and the README rather
  than faked. This matcher is a rule *unit test* engine, not a SIEM.

This module has no third-party imports beyond the standard library so that the
matcher itself is trivially portable and auditable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# --------------------------------------------------------------------------- #
# Single-field matching
# --------------------------------------------------------------------------- #

_NUMERIC_MODS = {"gt", "gte", "lt", "lte"}


def _get_field(event: dict, field: str) -> Any:
    """Case-insensitive field lookup. Returns None if the field is absent."""
    if field in event:
        return event[field]
    lowered = field.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def _as_str(value: Any) -> str:
    return "" if value is None else str(value)


def _match_scalar(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    """Match one field's actual value against one expected value + modifiers."""
    cased = "cased" in modifiers

    # Numeric comparisons -------------------------------------------------- #
    numeric_mod = next((m for m in modifiers if m in _NUMERIC_MODS), None)
    if numeric_mod is not None:
        try:
            a = float(actual)
            b = float(expected)
        except (TypeError, ValueError):
            return False
        return {
            "gt": a > b,
            "gte": a >= b,
            "lt": a < b,
            "lte": a <= b,
        }[numeric_mod]

    # `null` special value ------------------------------------------------- #
    if expected is None:
        return actual is None

    if actual is None:
        return False

    a_str = _as_str(actual)
    e_str = _as_str(expected)
    if not cased:
        a_str = a_str.lower()
        e_str = e_str.lower()

    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        return re.search(_as_str(expected), _as_str(actual), flags) is not None
    if "contains" in modifiers:
        return e_str in a_str
    if "startswith" in modifiers:
        return a_str.startswith(e_str)
    if "endswith" in modifiers:
        return a_str.endswith(e_str)

    # Plain equality (numbers compared numerically when both look numeric).
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual == expected
    try:
        return float(actual) == float(expected)
    except (TypeError, ValueError):
        return a_str == e_str


def _match_field(event: dict, raw_key: str, expected: Any) -> bool:
    """Match a single `field|modifiers: value(s)` entry against one event."""
    parts = raw_key.split("|")
    field = parts[0]
    modifiers = parts[1:]

    actual = _get_field(event, field)

    values = expected if isinstance(expected, list) else [expected]

    if "all" in modifiers:
        # Every listed value must match (AND across the list).
        return all(_match_scalar(actual, v, modifiers) for v in values)
    # Default list semantics: OR across the list.
    return any(_match_scalar(actual, v, modifiers) for v in values)


def _match_selection(event: dict, selection: Any) -> bool:
    """Match a named selection (a map, or a list of maps => OR) against one event."""
    if isinstance(selection, list):
        # List of maps / keywords => OR of each sub-selection.
        return any(_match_selection(event, sub) for sub in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, key, val) for key, val in selection.items())
    # A bare keyword string: treat as a full-text-ish match across all values.
    needle = _as_str(selection).lower()
    return any(needle in _as_str(v).lower() for v in event.values())


# --------------------------------------------------------------------------- #
# Condition expression evaluation
# --------------------------------------------------------------------------- #

class _ConditionEvaluator:
    """
    Tiny recursive-descent evaluator for the boolean part of a Sigma condition.
    `selection_results` maps selection-name -> bool (already computed for the
    event under consideration).
    """

    def __init__(self, selection_names: list[str]):
        self._names = selection_names

    def evaluate(self, condition: str, results: dict[str, bool]) -> bool:
        tokens = self._tokenize(condition)
        self._tokens = tokens
        self._pos = 0
        self._results = results
        value = self._parse_or()
        if self._pos != len(self._tokens):
            raise ValueError(f"Unparsed tokens in condition: {self._tokens[self._pos:]}")
        return value

    # --- tokenizer --- #
    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        # Pad parentheses so they split cleanly, then whitespace-split.
        spaced = condition.replace("(", " ( ").replace(")", " ) ")
        return spaced.split()

    # --- parser --- #
    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._peek() == "or":
            self._next()
            rhs = self._parse_and()
            value = value or rhs
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._peek() == "and":
            self._next()
            rhs = self._parse_not()
            value = value and rhs
        return value

    def _parse_not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok == "(":
            self._next()
            value = self._parse_or()
            if self._peek() != ")":
                raise ValueError("Missing closing parenthesis in condition")
            self._next()
            return value

        # Quantifier expressions: "1 of them", "all of them", "1 of sel*", ...
        if tok in ("1", "all"):
            quant = self._next()
            if self._peek() == "of":
                self._next()
                target = self._next()
                return self._eval_quantifier(quant, target)
            # Not a quantifier after all -> treat as a selection name literally.
            return self._results.get(quant, False)

        # Plain selection name.
        name = self._next()
        return self._results.get(name, False)

    def _eval_quantifier(self, quant: str, target: str) -> bool:
        if target == "them":
            matched = self._names
        elif target.endswith("*"):
            prefix = target[:-1]
            matched = [n for n in self._names if n.startswith(prefix)]
        else:
            matched = [n for n in self._names if n == target]

        flags = [self._results.get(n, False) for n in matched]
        if quant == "all":
            return all(flags) if flags else False
        # quant == "1"  (Sigma "1 of" means "any of")
        return any(flags)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

_AGG_RE = re.compile(
    r"""^\s*count\(\s*(?P<cnt>[\w.]*)\s*\)\s*
        (?:by\s+(?P<by>[\w.]+)\s+)?
        (?P<op>>=|<=|>|<|==)\s*(?P<num>\d+)\s*$""",
    re.VERBOSE,
)

_OPS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "==": lambda a, b: a == b,
}


def _evaluate_aggregation(
    base_matches: list[dict],
    agg_expr: str,
) -> bool:
    """
    Evaluate `count(field) by groupfield OP N` over the events that already
    satisfied the base condition. Fires if ANY group crosses the threshold.
    """
    m = _AGG_RE.match(agg_expr)
    if not m:
        raise ValueError(f"Unsupported aggregation expression: {agg_expr!r}")

    cnt_field = m.group("cnt") or None
    by_field = m.group("by")
    op = _OPS[m.group("op")]
    threshold = int(m.group("num"))

    # Group the matching events.
    groups: dict[Any, list[dict]] = {}
    for event in base_matches:
        key = _get_field(event, by_field) if by_field else "__all__"
        groups.setdefault(key, []).append(event)

    for events in groups.values():
        if cnt_field:
            # count(field) == number of DISTINCT values of that field.
            distinct = {_get_field(e, cnt_field) for e in events}
            value = len(distinct)
        else:
            # count() == number of events.
            value = len(events)
        if op(value, threshold):
            return True
    return False


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def rule_fires(rule: dict, events: Iterable[dict]) -> bool:
    """
    Return True if the Sigma `rule` (already parsed to a dict) fires against the
    given iterable of normalized log `events`.

    Non-aggregation rules fire if ANY single event satisfies the condition.
    Aggregation rules fire if the grouped count crosses the threshold.
    """
    events = list(events)
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Rule has no valid 'detection' block")

    condition = detection.get("condition")
    if not condition:
        raise ValueError("Rule detection has no 'condition'")
    if isinstance(condition, list):
        raise ValueError(
            "Multiple conditions (list form) are not supported by this matcher"
        )

    selection_names = [
        k for k in detection.keys() if k not in ("condition", "timeframe")
    ]
    evaluator = _ConditionEvaluator(selection_names)

    # Split off an aggregation suffix if present: "base | count(...) ...".
    if "|" in condition:
        base_condition, agg_expr = condition.split("|", 1)
        base_condition = base_condition.strip()
        agg_expr = agg_expr.strip()
    else:
        base_condition, agg_expr = condition.strip(), None

    def event_matches_base(event: dict) -> bool:
        results = {
            name: _match_selection(event, detection[name])
            for name in selection_names
        }
        return evaluator.evaluate(base_condition, results)

    if agg_expr is None:
        return any(event_matches_base(e) for e in events)

    base_matches = [e for e in events if event_matches_base(e)]
    if not base_matches:
        return False
    return _evaluate_aggregation(base_matches, agg_expr)
