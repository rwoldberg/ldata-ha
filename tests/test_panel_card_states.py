"""The panel card reads Leviton's own state names; these are the ones there are."""

import re
from pathlib import Path

CARD = (Path(__file__).parent.parent / "custom_components" / "ldata" / "www" / "ldata-panel-card.js").read_text()

# breakerCurrentState in Leviton's My Leviton app, with the cause the card
# should name for each (None: no cause to name).
CURRENT_STATES = {
    "AFCIMiswire": "miswire",
    "AFCIParallelFault": "parallel_arc_fault",
    "AFCISerialArc5AFault": "arc_fault",
    "AFCISerialArc10AFault": "arc_fault",
    "AFCISerialArc15AFault": "arc_fault",
    "AFCISerialArc20AFault": "arc_fault",
    "AFCISerialArc30AFault": "arc_fault",
    "GFCIFault": "ground_fault",
    "OverCurrentTripPhase1": "over_current",
    "OverCurrentTripPhase2": "over_current",
    "OverloadTrip": "overload",
    "ShortCircuitTrip": "short_circuit",
    "SoftwareTrip": None,
    "UpstreamFault": None,
    "ManualON": None,
    "ManualOFF": None,
    "COMMUNICATING": None,
    "CommunicationFailure": None,
    "NotCommunicating": None,
    "UNDEFINED": None,
}
# The states that app shows as tripped.
TRIPPED = {name for name, cause in CURRENT_STATES.items() if cause} | {"SoftwareTrip", "UpstreamFault"}
# breakerOperationalState in the same app: a breaker's own health, not a trip.
OPERATIONAL_STATES = [
    "AFCIGFCISelfTestFailure",
    "AFCISelfTestFailure",
    "EndOfLife",
    "GFCIErrorManualPhase1Failed",
    "GFCIErrorManualPhase2Failed",
    "GFCIErrorPhase1Failed",
    "GFCIErrorPhase2Failed",
    "GFCIErrorSTFailed",
    "GFCISCRBFailed",
    "GFCISelfTestFailureWithLVST",
    "Normal",
    "UNDEFINED",
]


def _causes() -> list[tuple[re.Pattern, str]]:
    table = re.search(r"const TRIP_CAUSES = \[(.*?)\n\];", CARD, re.DOTALL)
    assert table is not None
    rows = re.findall(r'\[/(.+?)/i, "([a-z_]+)"', table.group(1))
    assert rows
    return [(re.compile(pattern, re.IGNORECASE), key) for pattern, key in rows]


def _cause(state: str) -> str | None:
    return next((key for pattern, key in _causes() if pattern.search(state)), None)


def _is_trip(state: str) -> bool:
    rule = re.search(r"const isTripState = \(value\) => /(.+?)/i\.test", CARD)
    assert rule is not None
    return bool(re.search(rule.group(1), state, re.IGNORECASE)) or _cause(state) is not None


def test_each_of_levitons_states_gets_its_cause() -> None:
    assert {state: _cause(state) for state in CURRENT_STATES} == CURRENT_STATES


def test_card_calls_tripped_what_levitons_app_calls_tripped() -> None:
    assert {state for state in CURRENT_STATES if _is_trip(state)} == TRIPPED


def test_a_failing_breaker_is_not_taken_for_a_trip() -> None:
    # Their names have AFCI and GFCI in them too. A failed self-test used to
    # read as an arc fault.
    for state in OPERATIONAL_STATES:
        assert _cause(state) is None, state
        assert not _is_trip(state), state


def test_an_undefined_operational_state_is_not_an_alarm() -> None:
    # Leviton's app treats UNDEFINED like Normal.
    fine = re.search(r"const OP_FINE = \[(.*?)\];", CARD)

    assert fine is not None
    assert {"normal", "undefined"} <= set(re.findall(r'"([a-z]*)"', fine.group(1)))
