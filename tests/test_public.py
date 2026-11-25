"""公开测试：单点登出的基本契约。"""

from ssoout import (
    check_token,
    invalidate_local,
    logout_batch,
    parse_logout,
    propagate,
    targets_of,
)

TOKEN = "logout|v1|alice|idp-a|s-1"

ERP = {
    "system": "erp",
    "endpoint": "https://erp.example/sso/logout",
    "subject": "alice",
}
CRM = {
    "system": "crm",
    "endpoint": "https://crm.example/sso/logout",
    "subject": "alice",
}
HR = {
    "system": "hr",
    "endpoint": "https://hr.example/sso/logout",
    "subject": "alice",
}


def test_parse_logout_token():
    parsed = parse_logout(TOKEN)
    assert parsed.get("version") == "v1"
    assert parsed.get("subject") == "alice"
    assert parsed.get("session") == "s-1"
    assert parsed.get("issuer") == "idp-a"
    assert check_token(TOKEN, ["idp-a"]) is True
    assert check_token(TOKEN, ["idp-b"]) is False


def test_targets_of_lists_downstream_participants():
    registry = {"s-1": [ERP, CRM, HR, ERP]}
    targets = targets_of({"id": "s-1", "subject": "alice"}, registry)
    assert [target.get("system") for target in targets] == ["erp", "crm", "hr"]


def test_propagate_notifies_each_downstream():
    calls = []
    result = propagate([ERP, CRM, HR], lambda target: calls.append(target["system"]))
    assert calls == ["erp", "crm", "hr"]
    assert [record.get("system") for record in result.get("records", [])] == [
        "erp",
        "crm",
        "hr",
    ]
    assert result.get("complete") is True


def test_invalidate_local_session_immediately():
    store = {
        "s-1": {
            "subject": "alice",
            "active": True,
            "expires": 9000.0,
            "invalidated_at": None,
        }
    }
    report = invalidate_local(store, {"id": "s-1", "subject": "alice"}, 1000.0)
    entry = store["s-1"]
    assert entry["active"] is False
    assert entry["invalidated_at"] == 1000.0
    assert entry["expires"] <= 1000.0
    assert report.get("changed") is True


def test_logout_batch_keeps_sessions_independent():
    first_store = {
        "s-1": {
            "subject": "alice",
            "active": True,
            "expires": 9000.0,
            "invalidated_at": None,
        }
    }
    second_store = {
        "s-2": {
            "subject": "bob",
            "active": True,
            "expires": 9000.0,
            "invalidated_at": None,
        }
    }
    sessions = [
        {
            "session": {"id": "s-1", "subject": "alice"},
            "targets": [ERP, CRM],
            "store": first_store,
        },
        {
            "session": {"id": "s-2", "subject": "bob"},
            "targets": [HR],
            "store": second_store,
        },
    ]
    payload = logout_batch(sessions, lambda target: None, now=500.0)
    results = payload["results"]
    assert [item["session"] for item in results] == ["s-1", "s-2"]
    assert [record["system"] for record in results[1]["records"]] == ["hr"]
    assert results[1]["local"]["session"] == "s-2"
    assert second_store["s-2"]["active"] is False
    assert second_store["s-2"]["expires"] <= 500.0