"""Fill a template's __NAME__ placeholders from a dict of values."""
import re

PLACEHOLDER = re.compile(r"__([A-Z][A-Z0-9_]*)__")


def check_value(name: str, value) -> str:
    """A value must be a non-empty string that cannot break the JSON around it."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name}: value must be a non-empty string")
    if any(c in '"\\' or ord(c) < 32 for c in value):
        raise ValueError(f"{name}: value must not contain quotes, backslashes, or control characters")
    return value


def render(template: str, values: dict) -> str:
    """Replace every __NAME__ with values[name]. Every placeholder and every value must be used."""
    wanted = set(PLACEHOLDER.findall(template))
    given = {name.upper() for name in values}
    problems = []
    if wanted - given:
        problems.append("no value for " + ", ".join(sorted(wanted - given)))
    if given - wanted:
        problems.append("no placeholder for " + ", ".join(sorted(given - wanted)))
    if problems:
        raise ValueError("; ".join(problems))
    return PLACEHOLDER.sub(lambda m: check_value(m.group(1), values[m.group(1).lower()]), template)
