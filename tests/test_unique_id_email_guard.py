"""Unique ids must start with the coordinator's unique_id_prefix, never the account email."""

import re
from pathlib import Path

INTEGRATION = Path(__file__).parents[1] / "custom_components" / "ldata"

# An f-string placeholder that reads the email: "{coordinator.user}-..." or
# "{self.coordinator.user}_...". The attribute itself is set in coordinator.py
# and never appears inside braces.
EMAIL_PLACEHOLDER = re.compile(r"\{(?:self\.)?coordinator\.user\}")


def test_no_unique_id_is_built_from_the_account_email() -> None:
    offenders = [
        f"{path.name}:{number}: {line.strip()}"
        for path in sorted(INTEGRATION.glob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if EMAIL_PLACEHOLDER.search(line)
    ]
    assert not offenders, (
        "Build unique ids from coordinator.unique_id_prefix, not coordinator.user:\n"
        + "\n".join(offenders)
    )
