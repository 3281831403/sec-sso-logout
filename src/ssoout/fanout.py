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

_TOKEN_VERSION = "v1"
_TOKEN_SEGMENTS = 5


def parse_logout(token):
    """解析登出令牌，返回版本、主体、签发方与会话。

    令牌必须是五段竖线分隔字符串：logout|v1|主体|签发方|会话标识。
    任何一段缺失或类型/版本不符都抛出 ValueError。
    """
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
    if not subject:
        raise ValueError("logout token is missing subject")
    if not issuer:
        raise ValueError("logout token is missing issuer")
    if not session:
        raise ValueError("logout token is missing session")
    return {
        "version": version,
        "subject": subject,
        "issuer": issuer,
        "session": session,
    }


def check_token(token, trusted):
    """判断登出令牌是否来自受信签发方。

    签发方必须与受信列表中的某一项完全相同（完整匹配，不做前缀/后缀
    匹配）；令牌不合法、签发方缺失或不在受信列表内都返回 False。
    """
    try:
        parsed = parse_logout(token)
    except (TypeError, ValueError):
        return False
    issuer = parsed.get("issuer")
    if not issuer:
        return False
    for name in trusted or ():
        if isinstance(name, str) and issuer == name:
            return True
    return False


def targets_of(session, registry):
    """返回该会话需要通知的全部下游参与者，同一参与者只保留一次。"""
    session_id = session.get("id") if isinstance(session, dict) else session
    if not session_id:
        return []
    entries = (registry or {}).get(session_id) or []
    unique = []
    seen = set()
    for entry in entries:
        name = entry.get("system") if isinstance(entry, dict) else None
        if name in seen:
            continue
        seen.add(name)
        unique.append(dict(entry) if isinstance(entry, dict) else entry)
    return unique


def _record_for(target, ok, attempts, error):
    """根据参与者与通知结果构造一条传播记录。"""
    return {
        "system": target.get("system"),
        "endpoint": target.get("endpoint"),
        "subject": target.get("subject"),
        "ok": ok,
        "attempts": attempts,
        "error": error,
    }


def propagate(targets, notifier):
    """逐个通知全部下游参与者，并记录每一次通知的结果。

    任何一个参与者通知抛错都只记为该参与者失败，不影响其他参与者；
    complete 仅在全部参与者都通知成功时为真。
    """
    records = []
    for target in list(targets or []):
        try:
            notifier(target)
        except Exception as exc:  # 单个参与者失败不影响其他参与者
            records.append(_record_for(target, False, 1, str(exc) or exc.__class__.__name__))
        else:
            records.append(_record_for(target, True, 1, None))
    return {
        "records": records,
        "complete": all(record["ok"] for record in records),
    }


def retry_failed(result, notifier):
    """只重试失败的参与者，已经成功的不再重复通知。

    成功记录原样保留（attempts 不变）；失败记录重新通知并累加尝试次数。
    没有失败项时不会调用 notifier，因此重复重试是幂等的。
    """
    records = []
    for record in (result or {}).get("records") or []:
        if record.get("ok"):
            # 已成功的下游不得再被重复通知，原样保留
            records.append(dict(record))
            continue
        target = {
            "system": record.get("system"),
            "endpoint": record.get("endpoint"),
            "subject": record.get("subject"),
        }
        attempts = int(record.get("attempts") or 1) + 1
        try:
            notifier(target)
        except Exception as exc:
            records.append(_record_for(target, False, attempts, str(exc) or exc.__class__.__name__))
        else:
            records.append(_record_for(target, True, attempts, None))
    return {
        "records": records,
        "complete": all(record["ok"] for record in records),
    }


def invalidate_local(store, session, now):
    """让本地会话立即失效，而不是等待票据自然过期。

    置 active=False、invalidated_at=now，并把 expires 压缩到不晚于 now，
    使该条目立刻不再被判定为有效。重复登出同一会话保持幂等：已失效的
    条目不会被二次修改，报告 changed=False 且结果与首次一致。
    """
    session_id = session.get("id") if isinstance(session, dict) else session
    subject = session.get("subject") if isinstance(session, dict) else None
    entry = (store or {}).get(session_id)
    if entry is None:
        return {
            "session": session_id,
            "subject": subject,
            "changed": False,
            "active": False,
            "invalidated_at": None,
            "expires": None,
        }

    already_invalid = entry.get("active") is False
    if already_invalid:
        # 幂等：重复登出不改动条目，返回与既有状态一致的报告
        return {
            "session": session_id,
            "subject": entry.get("subject", subject),
            "changed": False,
            "active": False,
            "invalidated_at": entry.get("invalidated_at"),
            "expires": entry.get("expires"),
        }

    entry["active"] = False
    entry["invalidated_at"] = now
    # 立即失效：过期时间不得晚于当前时间
    entry["expires"] = min(float(entry.get("expires", now)), float(now))
    return {
        "session": session_id,
        "subject": entry.get("subject", subject),
        "changed": True,
        "active": False,
        "invalidated_at": now,
        "expires": entry["expires"],
    }


def validate_result(result, targets):
    """检查一次传播的结果，返回发现的问题列表；健康结果返回空列表。"""
    problems = []
    records = (result or {}).get("records") or []
    target_list = list(targets or [])

    expected = []
    for target in target_list:
        name = target.get("system") if isinstance(target, dict) else None
        if name not in expected:
            expected.append(name)

    seen = set()
    notified = []
    for record in records:
        system = record.get("system")
        if system in seen:
            problems.append("duplicate:{}".format(system))
        else:
            seen.add(system)
            notified.append(system)
        if not record.get("subject"):
            problems.append("missing-subject:{}".format(system))
        if not record.get("ok"):
            problems.append("failed:{}".format(system))

    for name in expected:
        if name not in seen:
            problems.append("missing-record:{}".format(name))
    return problems


def logout_batch(sessions, notifier, now):
    """批量登出多个会话，每个会话各自独立处理。

    每个会话分别取自己的下游做传播、分别失效自己的本地存储，结果互不
    共用；单个会话处理失败不影响其他会话。
    """
    results = []
    for item in sessions or []:
        session = item.get("session") or {}
        session_id = session.get("id") if isinstance(session, dict) else session
        # 每个会话独立取自己的下游、独立传播、独立失效
        propagation = propagate(item.get("targets") or [], notifier)
        local = invalidate_local(item.get("store") or {}, session, now)
        results.append(
            {
                "session": session_id,
                "records": propagation["records"],
                "complete": propagation["complete"],
                "local": local,
            }
        )
    return {
        "results": results,
        "complete": all(item["complete"] for item in results),
    }
