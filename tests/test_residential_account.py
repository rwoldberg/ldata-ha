"""The residential account lookup succeeds only when it finds an account id.

get_residential_account() starts from an empty account id and checked
"is not None", so permissions that name no residentialAccountId made it
return True with the id still empty. status() then looked up
ResidentialAccounts//residences and ResidentialAccounts/, and the failure
of the second cleared the tokens.
"""

from custom_components.ldata.ldata_service import LDATAService


def _service(permissions) -> LDATAService:
    service = LDATAService("", "", None)
    service.auth_token, service.userid = "token", "user"
    service._residence_api_get = lambda *_args, **_kwargs: permissions
    return service


def test_permissions_naming_no_account_fail_the_lookup() -> None:
    service = _service([{"residenceId": 7, "userId": "user"}])

    assert service.get_residential_account() is False
    assert not service.account_id


def test_a_null_account_id_fails_the_lookup() -> None:
    service = _service([{"residenceId": 7, "userId": "user", "residentialAccountId": None}])

    assert service.get_residential_account() is False


def test_the_first_account_id_found_is_used() -> None:
    service = _service([
        {"residenceId": 7, "userId": "user", "residentialAccountId": None},
        {"residenceId": 8, "userId": "user", "residentialAccountId": "account-2"},
    ])

    assert service.get_residential_account() is True
    assert service.account_id == "account-2"
