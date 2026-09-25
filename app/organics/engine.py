"""阈值判定与维护窗口计算的纯函数。

不触碰数据库，全部输入显式给出，便于对乱序时间、跨日维护窗口等场景
做确定性单元测试。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.organics.clock import parse_ts


@dataclass(frozen=True)
class Rule:
    metric: str
    min_value: float | None
    max_value: float | None
    escalate_after_minutes: int
    critical_after_minutes: int
    expect_interval_minutes: int | None

    @classmethod
    def from_dict(cls, value: dict) -> "Rule":
        return cls(
            metric=value["metric"],
            min_value=value.get("min_value"),
            max_value=value.get("max_value"),
            escalate_after_minutes=int(value.get("escalate_after_minutes", 30)),
            critical_after_minutes=int(value.get("critical_after_minutes", 120)),
            expect_interval_minutes=value.get("expect_interval_minutes"),
        )


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime
    metric: str
    location_code: str

    @classmethod
    def from_row(cls, row) -> "Window":
        return cls(parse_ts(row["start_at"]), parse_ts(row["end_at"]), row["metric"], row["location_code"])

    def covers(self, moment: datetime, metric: str, location_code: str) -> bool:
        if self.metric and self.metric != metric:
            return False
        if self.location_code and self.location_code != location_code:
            return False
        return self.start <= moment <= self.end


def classify(value: float, rule: Rule) -> str | None:
    """返回越界方向：'low' / 'high'，正常为 None。"""
    if rule.min_value is not None and value < rule.min_value:
        return "low"
    if rule.max_value is not None and value > rule.max_value:
        return "high"
    return None


def in_maintenance(moment: datetime, windows: list[Window], metric: str, location_code: str) -> bool:
    return any(window.covers(moment, metric, location_code) for window in windows)


def level_for(duration_minutes: float, rule: Rule) -> str:
    if duration_minutes >= rule.critical_after_minutes:
        return "critical"
    if duration_minutes >= rule.escalate_after_minutes:
        return "serious"
    return "warning"


def _gap_covered_by_maintenance(prev: datetime, current: datetime, windows: list[Window], metric: str, location_code: str) -> bool:
    """判断 (prev, current) 整段缺测区间是否被维护窗口（并集）完全覆盖。

    区间相交后做离散化合并；只有整段都落在适用窗口内才抑制缺测告警，
    跨日窗口同样适用。
    """
    segments: list[tuple[datetime, datetime]] = []
    for window in windows:
        if window.metric and window.metric != metric:
            continue
        if window.location_code and window.location_code != location_code:
            continue
        left = max(prev, window.start)
        right = min(current, window.end)
        if left < right:
            segments.append((left, right))
    if not segments:
        return False
    segments.sort()
    cursor = prev
    for left, right in segments:
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= current:
            return True
    return cursor >= current


def missing_gaps(
    times: list[datetime],
    rule: Rule,
    windows: list[Window],
    location_code: str,
) -> list[tuple[datetime, datetime]]:
    """按时间排序后，找出超出期望采集间隔、且未被维护窗口覆盖的缺口。"""
    if not rule.expect_interval_minutes or len(times) < 2:
        return []
    ordered = sorted(times)
    gaps: list[tuple[datetime, datetime]] = []
    for prev, current in zip(ordered, ordered[1:]):
        delta = (current - prev).total_seconds() / 60.0
        if delta > rule.expect_interval_minutes and not _gap_covered_by_maintenance(
            prev, current, windows, rule.metric, location_code
        ):
            gaps.append((prev, current))
    return gaps
