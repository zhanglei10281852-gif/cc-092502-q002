"""判定引擎纯函数测试：跨日维护窗口、缺口并集覆盖、升级时长。"""

from __future__ import annotations

from datetime import timedelta

from app.organics.clock import parse_ts
from app.organics.engine import Rule, Window, classify, level_for, missing_gaps


def rule(interval=10):
    return Rule(
        metric="temperature",
        min_value=2.0,
        max_value=8.0,
        escalate_after_minutes=30,
        critical_after_minutes=120,
        expect_interval_minutes=interval,
    )


def window(start, end, metric="", location=""):
    return Window(parse_ts(start), parse_ts(end), metric, location)


def test_classify_directions():
    r = rule()
    assert classify(1.9, r) == "low"
    assert classify(8.1, r) == "high"
    assert classify(5.0, r) is None
    assert level_for(29, r) == "warning"
    assert level_for(30, r) == "serious"
    assert level_for(120, r) == "critical"


def test_missing_gap_basic():
    t0 = parse_ts("2026-09-25T10:00:00+00:00")
    times = [t0, t0 + timedelta(minutes=60)]
    gaps = missing_gaps(times, rule(), [], "L1")
    assert len(gaps) == 1


def test_cross_day_maintenance_window_suppresses_missing():
    # 缺口从 23:40 跨午夜到次日 00:40，维护窗口 23:00-01:30 完全覆盖
    t0 = parse_ts("2026-09-25T23:40:00+00:00")
    t1 = parse_ts("2026-09-26T00:40:00+00:00")
    win = window("2026-09-25T23:00:00+00:00", "2026-09-26T01:30:00+00:00")
    assert missing_gaps([t0, t1], rule(), [win], "L1") == []


def test_two_windows_union_covers_gap():
    # 两个相邻窗口拼合后恰好覆盖整段缺口
    t0 = parse_ts("2026-09-25T10:00:00+00:00")
    t1 = parse_ts("2026-09-25T11:00:00+00:00")
    windows = [
        window("2026-09-25T10:00:00+00:00", "2026-09-25T10:30:00+00:00"),
        window("2026-09-25T10:30:00+00:00", "2026-09-25T11:00:00+00:00"),
    ]
    assert missing_gaps([t0, t1], rule(), windows, "L1") == []


def test_partial_coverage_still_reports_gap():
    t0 = parse_ts("2026-09-25T10:00:00+00:00")
    t1 = parse_ts("2026-09-25T11:00:00+00:00")
    win = window("2026-09-25T10:00:00+00:00", "2026-09-25T10:20:00+00:00")
    gaps = missing_gaps([t0, t1], rule(), [win], "L1")
    assert len(gaps) == 1


def test_window_metric_and_location_scoping():
    t0 = parse_ts("2026-09-25T10:00:00+00:00")
    t1 = parse_ts("2026-09-25T11:00:00+00:00")
    # 窗口是别的指标 / 别的库位，不能抑制缺测
    assert missing_gaps([t0, t1], rule(), [window("2026-09-25T09:00:00+00:00", "2026-09-25T12:00:00+00:00", metric="humidity")], "L1")
    assert missing_gaps([t0, t1], rule(), [window("2026-09-25T09:00:00+00:00", "2026-09-25T12:00:00+00:00", location="OTHER")], "L1")
    assert missing_gaps([t0, t1], rule(), [window("2026-09-25T09:00:00+00:00", "2026-09-25T12:00:00+00:00", location="L1")], "L1") == []
