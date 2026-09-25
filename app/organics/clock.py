"""统一的 UTC 时间解析与序列化。

传感器读数来自离线批次，时间戳可能带偏移（``2026-09-25T08:00:00+08:00``）、
可能为朴素 UTC（``...Z`` / 无后缀）。全部规范为带时区的 UTC ``datetime``，
入库统一为 ISO 字符串，比较一律使用 ``datetime``，避免字符串比较被
``Z`` / ``+00:00`` 的词法差异破坏。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"


def parse_ts(value: str | datetime) -> datetime:
    """把任意 ISO-8601 时间解析为带时区的 UTC datetime。"""
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_ts(dt: datetime) -> str:
    return parse_ts(dt).strftime(ISO_FMT)


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def now() -> str:
    return format_ts(now_dt())


def add_minutes(dt: datetime, minutes: int) -> datetime:
    return parse_ts(dt) + timedelta(minutes=minutes)
