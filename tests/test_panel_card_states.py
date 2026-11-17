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


def test_every_failing_operational_state_needs_service() -> None:
    # Leviton's app shows any operational state but Normal and UNDEFINED as
    # needing service. The breaker locks out: the card draws it tripped, with
    # the AF and GF LEDs flashing fast, for either pole.
    fine = re.search(r"const OP_FINE = \[(.*?)\];", CARD)
    assert fine is not None
    fine_states = set(re.findall(r'"([a-z]*)"', fine.group(1)))
    for state in OPERATIONAL_STATES:
        assert (state.lower() in fine_states) == (state in {"Normal", "UNDEFINED"}), state

    source = re.sub(r"\s+", " ", CARD)
    assert "const failed = !!ops && (!opIsFine(op) || !opIsFine(op2));" in source
    assert "ops.attributes.second_pole_state" in source
    assert 'else if (tripped || failed) vis = "tripped";' in source
    assert "tripped || failed || (heldOff && s.gen1) ? \"trip\"" in source
    assert 's.ledAf = !s.hasAf ? "off" : failed ? "fast"' in source
    assert 's.ledGf = !s.hasGf ? "off" : failed ? "fast"' in source


def test_led_blink_rates_follow_levitons_tables() -> None:
    # Per flash: Gen 2 parallel arc fault once a second (SC-050923), Gen 1
    # every half second (SC-030123), a failed self-test 0.1 s on and off,
    # a miswired neutral once every three seconds.
    def period(name: str) -> float:
        rule = re.search(rf'\[data-af="{name}"\] > \.led--af[^{{]*\{{ animation: ldp-blink(?:-slow)? ([0-9.]+)s', CARD)
        assert rule is not None, name
        return float(rule.group(1))

    assert period("blink") == 1
    assert period("quick") == 0.5
    # Identify: 1.5 s on, 1.5 s off, on Gen 1 and Gen 2 breakers alike.
    assert period("ident") == 3
    assert period("fast") == 0.2
    assert period("slow") == 3
    assert re.search(r'const GEN1_BLINK = \{ blink: "quick" \};', CARD)


def test_identify_and_a_miswire_on_an_afci_only_breaker() -> None:
    source = re.sub(r"\s+", " ", CARD)
    # Identify uses its own rate on the status LED and on a Gen 1 breaker's AF/GF.
    assert 's.led = s.blinkOn ? "ident"' in source
    assert 'const ident = s.gen1 && s.blinkOn ? "ident" : "off";' in source
    # Leviton: "Blinking LED (3-sec): Neutral miswire (AF/GF/Dual-Function)".
    # Without a GF LED, the AF LED gives the miswire's three-second blink.
    assert 'cause.key === "miswire" && !s.hasGf ? cause.gf' in source
    miswire = re.search(r'\[/\^AFCIMiswire\$/i, "miswire", "(\w+)", "(\w+)"\]', CARD)
    assert miswire is not None and miswire.groups() == ("off", "slow")


def test_a_breaker_that_needs_service_is_announced_that_way() -> None:
    """Screen readers and the tooltip say what the label shows."""
    source = re.sub(r"\s+", " ", CARD)
    assert 'tripped: t(s.failed ? "card.state.service" : "card.state.tripped")' in source
    # The tooltip names the state of every tripped breaker, with its cause if known.
    assert 'cause ? `${stateWord} · ${cause}` : s.vis === "tripped" ? stateWord : null' in source


def test_sub_panel_popup_shows_it_with_this_cards_settings() -> None:
    popup = re.search(r"\n  _openSubPanel\(deviceId, name\) \{\n(.*?)\n  \}\n", CARD, re.DOTALL)
    assert popup is not None
    config = re.search(r"card\.setConfig\(\{(.*?)\}\);", popup.group(1), re.DOTALL)
    assert config is not None
    given = set(re.findall(r"(\w+): cfg\.(\w+),", config.group(1)))
    assert given == {(name, name) for name in ("appearance", "confirm", "toggle", "show_power", "show_alarms", "show_panel_info")}
    # What belongs to this card's own panel stays here.
    for option in ("rotate_180", "main_breaker", "sub_panels"):
        assert option not in config.group(1), option


def test_main_breaker_comes_from_the_card_or_else_the_integration() -> None:
    # Kept with the panel's layout, so it is still drawn during an outage.
    layout = re.search(r"const PANEL_LAYOUT = \[(.*?)\];", CARD)
    assert layout is not None and '"main_breaker"' in layout.group(1)
    helper = re.search(r"\n  _mainBreaker\(layout\) \{\n(.*?)\n  \}\n", CARD, re.DOTALL)
    assert helper is not None
    body = helper.group(1)
    # The card's own setting wins over the integration's.
    assert body.index("this._config.main_breaker") < body.index("layout.main_breaker")
    # The drawing, the share in use and the rebuild key all go through it.
    assert "const main = m.mainBreaker;" in CARD
    assert "this._mainBreaker(layout)].filter" in CARD
    assert "cfg.main_breaker" not in CARD
