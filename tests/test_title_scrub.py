"""Tests for removing the account password from legacy entry titles."""

from unittest.mock import MagicMock

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.ldata import _title_without_password


def _entry(title: str, data: dict) -> MagicMock:
    entry = MagicMock()
    entry.title = title
    entry.data = data
    return entry


def test_legacy_title_with_password_is_replaced() -> None:
    entry = _entry(
        "Leviton LDATA (('user@example.com', 'hunter2', False))",
        {CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    assert _title_without_password(entry) == "Leviton LDATA (user@example.com)"


def test_legacy_email_key_is_used() -> None:
    entry = _entry(
        "Leviton LDATA (('user@example.com', 'hunter2'))",
        {"email": "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    assert _title_without_password(entry) == "Leviton LDATA (user@example.com)"


def test_clean_title_is_left_alone() -> None:
    entry = _entry(
        "Leviton LDATA (Home)",
        {CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    assert _title_without_password(entry) is None


def test_entry_without_password_is_left_alone() -> None:
    entry = _entry("Leviton LDATA (Home)", {CONF_USERNAME: "user@example.com"})
    assert _title_without_password(entry) is None


def test_password_inside_username_renames_only_once() -> None:
    data = {CONF_USERNAME: "pass1234@example.com", CONF_PASSWORD: "pass1234"}
    entry = _entry("Leviton LDATA (('pass1234@example.com', 'pass1234'))", data)
    new_title = _title_without_password(entry)
    assert new_title == "Leviton LDATA (pass1234@example.com)"
    # After the rename the title still contains the password, as part of the
    # username, but there is nothing left to do.
    assert _title_without_password(_entry(new_title, data)) is None


def test_entry_without_username_is_left_alone() -> None:
    entry = _entry("Leviton LDATA ((None, 'hunter2'))", {CONF_PASSWORD: "hunter2"})
    assert _title_without_password(entry) is None
