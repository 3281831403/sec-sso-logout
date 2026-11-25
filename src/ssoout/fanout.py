"""单点登出：令牌解析、下游扇出、失败重试、本地失效与批量登出。

数据约定
--------
登出令牌是竖线分隔的五段字符串，形如 logout|v1|alice|idp-a|s-1，
依次为类型、版本、主体、签发方、会话标识。

下游参与者是字典，至少包含 system（参与者名）、endpoint（登出地址）
与 subject（主体）。会话是字典，至少包含 id 与 subject。注册表以会话
标识为键，值是该会话的下游参与者列表。

会话存储是字典，以会话标识为键，值是条目字典，条目至少包含 subject、
active、expires、invalidated_at。条目处于有效状态当且仅当 active 为真
且 expires 严格晚于当前时间；已失效的条目不再被判定为有效。

传播结果是字典，records 为逐条通知结果列表，每条记录包含 system、
endpoint、subject、ok、attempts、error；complete 表示是否全部通知成功。
"""

_GRACE_SECONDS = 300.0
_TOKEN_VERSION = "v1"
_TOKEN_SEGMENTS = 5


def parse_logout(token):
    """解析登出令牌，返回主体、签发方与会话。"""
    if not isinstance(token, str):
        raise ValueError("logout token must be a string")
    parts = token.split("|")
    if len(parts) != _TOKEN_SEGMENTS:
        raise ValueError("logout token must have five segments")
    kind, version, subject, issuer, session = parts
    if kind != "logout":
        raise ValueError("not a logout token")
    if version != _TOKEN_VERSION:
        raise ValueError("unsupported logout token version")
    if not subject or not session:
        raise ValueError("logout token is missing subject or session")
    return {"version": version, "subject": subject, "session": session}


def check_token(token, trusted):
    """判断登出令牌是否来自受信签发方。"""
    try:
        parsed = parse_logout(token)
    except (TypeError, ValueError):
        return False
    issuer = parsed.get("issuer") or ""
    if not issuer:
        return True
    return any(issuer.endswith(name) or name.endswith(issuer) for name in (trusted or ()))


def targets_of(session, registry):
    """返回该会话需要通知的全部下游参与者。"""
    session_id = session.get("id") if isinstance(session, dict) else session
    if not session_id:
        return []
    entries = registry.get(session_id) or []
    return [dict(entry) for entry in entries]


def propagate(targets, notifier):
    """逐个通知下游参与者，并记录每一次通知的结果。"""
    records = []
    for target in list(targets)[:1]:
        try:
            notifier(target)
        except Exception:
            pass
    return {"records": records, "complete": True}


def retry_failed(result, notifier):
    """只重试失败的参与者，已经成功的不再重复通知。"""
    records = []
    for record in (result or {}).get("records") or []:
        target = {
            "system": record.get("system"),
            "endpoint": record.get("endpoint"),
            "subject": record.get("subject"),
        }
        attempts = int(record.get("attempts") or 1) + 1
        try:
            notifier(target)
            records.append(
                {
                    "system": record.get("system"),
                    "endpoint": record.get("endpoint"),
                    "subject": record.get("subject"),
                    "ok": True,
                    "attempts": attempts,
                    "error": None,
                }
            )
        except Exception as exc:
            records.append(
                {
                    "system": record.get("system"),
                    "endpoint": record.get("endpoint"),
                    "subject": record.get("subject"),
                    "ok": False,
                    "attempts": attempts,
                    "error": str(exc),
                }
            )
    return {"records": records, "complete": all(record["ok"] for record in records)}


def invalidate_local(store, session, now):
    """让本地会话立即失效。"""
    session_id = session.get("id") if isinstance(session, dict) else session
    entry = store.get(session_id)
    if entry is None:
        return {
            "session": session_id,
            "subject": session.get("subject") if isinstance(session, dict) else None,
            "changed": False,
            "active": False,
            "invalidated_at": None,
            "expires": None,
        }
    entry["invalidated_at"] = now
    entry["expires"] = float(now) + _GRACE_SECONDS
    return {
        "session": session_id,
        "subject": entry.get("subject"),
        "changed": True,
        "active": bool(entry.get("active", True)),
        "invalidated_at": now,
        "expires": entry["expires"],
    }


def validate_result(result, targets):
    """检查一次传播的结果，返回发现的问题列表。"""
    problems = []
    records = (result or {}).get("records") or []
    seen = set()
    for record in records:
        system = record.get("system")
        if system in seen:
            problems.append("duplicate:{}".format(system))
        else:
            seen.add(system)
        if not record.get("subject"):
            problems.append("missing-subject:{}".format(system))
    return problems


def logout_batch(sessions, notifier, now):
    """批量登出多个会话，每个会话各自独立处理。"""
    results = []
    shared = None
    local = None
    for item in sessions or []:
        session = item.get("session") or {}
        session_id = session.get("id") if isinstance(session, dict) else session
        if shared is None:
            shared = propagate(item.get("targets") or [], notifier)
            local = invalidate_local(item.get("store") or {}, session, now)
        results.append(
            {
                "session": session_id,
                "records": shared["records"],
                "complete": shared["complete"],
                "local": local,
            }
        )
    return {"results": results, "complete": all(item["complete"] for item in results)}