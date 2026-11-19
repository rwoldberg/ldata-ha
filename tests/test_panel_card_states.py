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
    for option in ("rotate_180", "load_capacity", "main_breaker", "sub_panels"):
        assert option not in config.group(1), option


def test_capacity_comes_from_the_card_or_else_the_integration() -> None:
    # Kept with the panel's layout, so it still counts during an outage.
    layout = re.search(r"const PANEL_LAYOUT = \[(.*?)\];", CARD)
    assert layout is not None and '"load_capacity"' in layout.group(1)
    helper = re.search(r"\n  _capacity\(layout\) \{\n(.*?)\n  \}\n", CARD, re.DOTALL)
    assert helper is not None
    body = helper.group(1)
    # The card's own load_capacity wins over the integration's.
    assert body.index("this._config.load_capacity") < body.index("layout.load_capacity")
    # The integration's attribute is load_capacity now, not main_breaker.
    assert not re.search(r"layout\.main_breaker\b(?!_)", CARD)
    assert '"main_breaker"' not in layout.group(1)
    # The drawing, the share in use and the rebuild key all go through it.
    assert "const main = m.mainBreaker;" in CARD
    assert "this._capacity(layout)].filter" in CARD
    assert "cfg.main_breaker" not in CARD and "cfg.load_capacity" not in CARD


def test_old_main_breaker_setting_still_works() -> None:
    """load_capacity was main_breaker in the first test builds: such a dashboard keeps working."""
    helper = re.search(r"\nfunction currentOptions\(config\) \{\n(.*?)\n\}\n", CARD, re.DOTALL)
    assert helper is not None
    body = helper.group(1)
    assert 'const { main_breaker: capacity, ...rest } = config;' in body
    # The new name wins when both are set.
    assert '"load_capacity" in rest ? rest : { ...rest, load_capacity: capacity }' in body
    # The card and its editor both read a dashboard through it.
    assert CARD.count("config = currentOptions(config);") == 1
    assert "this._config = currentOptions(config || {});" in CARD
    # The editor offers, and saves, only the new name.
    schema = re.search(r"\nfunction editorSchema\(t\) \{\n(.*?)\n\}\n", CARD, re.DOTALL)
    assert schema is not None
    assert '{ name: "load_capacity",' in schema.group(1) and '"main_breaker"' not in schema.group(1)
    assert 'load_capacity: "editor.load_capacity",' in CARD and 'load_capacity: "editor.load_capacity_help",' in CARD


def test_the_main_breaker_turns_with_the_panel() -> None:
    """Leviton reports which way up the panel is; the main breaker is next to positions 1 and 2, at the bottom of one turned 180°."""
    layout = re.search(r"const PANEL_LAYOUT = \[(.*?)\];", CARD)
    assert layout is not None and '"panel_type"' in layout.group(1) and '"orientation"' in layout.group(1)
    assert '"main_breaker_position"' not in layout.group(1)
    helper = re.search(r"\n  _upsideDown\(layout\) \{\n(.*?)\n  \}\n", CARD, re.DOTALL)
    assert helper is not None
    body = helper.group(1)
    # The card's own rotate_180, else the way up Leviton reports the panel.
    # The panel type has no say in it.
    assert body.index("this._config.rotate_180") < body.index("orientation")
    assert "return Number(layout && layout.orientation) === 180;" in body
    assert "panel_type" not in body
    # One answer for the breakers, their numbers and the main breaker alike,
    # and the rebuild key.
    assert "const rotate = this._upsideDown(ca);" in CARD
    assert "this._computeLayout(slots, rotate)" in CARD
    assert "const structKey = JSON.stringify([\n      rotate," in CARD
    assert "const low = !!(main && m.rotate);" in CARD
    assert '${low ? " main-low" : ""}' in CARD
    assert "_mainLow" not in CARD
    low = re.search(r"\.main-low \.main \{([^}]*)\}", CARD)
    assert low is not None and "grid-row: -2" in low.group(1)
    # The room it needs moves to the bottom row with it.
    assert re.search(r"\.has-main\.main-low \{ --mainh: 0px; --mainh-low: ", CARD)
    assert "+ var(--mainh-low, 0px));" in CARD


def test_sub_panel_draws_no_main_breaker_but_its_capacity_counts() -> None:
    """A sub-panel, fed from a main breaker by the meter, say: no main breaker in it, but the share in use stays."""
    helper = re.search(r"\n  _mainDrawn\(layout\) \{\n(.*?)\n  \}\n", CARD, re.DOTALL)
    assert helper is not None
    # Only a main panel that doesn't hide it has one: a load center is a
    # sub-panel until the integration's options say otherwise.
    assert 'return layout && layout.panel_type === "main" ? this._capacity(layout) : null;' in helper.group(1)
    # The drawing and the rebuild key go by what is drawn...
    assert "mainBreaker: this._mainDrawn(ca)," in CARD
    assert "this._mainDrawn(ca)," in CARD.split("const structKey")[1].split("]);")[0]
    # ...and the share in use by the capacity, drawn or not.
    assert "this._capacity(layout)].filter" in CARD
