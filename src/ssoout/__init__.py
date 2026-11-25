"""单点登出的令牌校验、下游扇出、失败重试、本地失效与批量入口。"""

from .fanout import (
    check_token,
    invalidate_local,
    logout_batch,
    parse_logout,
    propagate,
    retry_failed,
    targets_of,
    validate_result,
)

__all__ = [
    "parse_logout",
    "check_token",
    "targets_of",
    "propagate",
    "retry_failed",
    "invalidate_local",
    "validate_result",
    "logout_batch",
]