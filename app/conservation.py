"""有机遗物保护处置模块。

覆盖：遗物登记（临时编号/材质判断/出土环境/容器/保管位置）、离线传感批次导入、
可版本化阈值方案、去重告警与按持续时间升级、维护窗口内缺测抑制、处置单租约
（领取/转交/完成/退回，重启后可恢复）、包装合并拆分的完整链路、敏感库位按权限
隐藏，以及确定性离线重放。

告警语义：
- 阈值越界形成"越界片段"（连续越界读数），同一片段只产生一条告警（去重），
  片段持续时间跨过方案中的升级阈值时级别单调上升（warning -> elevated -> critical）。
- 片段由该容器+指标的全部历史读数重算，因此读数乱序到达不影响最终状态。
- 缺测检测在首个读数之后启动：相邻读数间隔（扣除维护窗口覆盖时间）超过
  missing_after_minutes 才产生缺测告警，维护窗口（可跨日）内的缺测不会误报。
- 重放（replay）与导入共用同一评估函数，相同输入得到确定相同的告警与待办摘要。
"""
from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import connection, now, transaction
from app.security import stable_json
from app.service import ResearchService, ServiceError

CATEGORIES = ("wood", "textile", "rope")
METRICS = ("temperature", "humidity", "ph", "conductivity")
ORDER_TYPES = ("wet_storage", "packaging", "transport", "lab_handover")
ORDER_RESULT_STATUS = {
    "wet_storage": "stored",
    "packaging": "stored",
    "transport": "transferred",
    "lab_handover": "transferred",
}
SEVERITY_RANK = {"warning": 0, "elevated": 1, "critical": 2}

LEAD_ROLES = {"owner", "researcher"}
REGISTRAR_ROLES = {"owner", "researcher", "recorder"}
STAFF_ROLES = {"owner", "researcher", "conservator"}
OPERATOR_ROLES = {"owner", "researcher", "recorder", "conservator"}
MEMBER_ROLES = OPERATOR_ROLES | {"reviewer", "viewer"}
SENSITIVE_LOCATION_ROLES = {"owner", "researcher", "conservator"}

CONSERVATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_locations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 code TEXT NOT NULL,
 name TEXT NOT NULL,
 sensitive INTEGER NOT NULL DEFAULT 0 CHECK(sensitive IN (0,1)),
 created_at TEXT NOT NULL,
 UNIQUE(project_id,code)
);
CREATE TABLE IF NOT EXISTS containers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 code TEXT NOT NULL,
 kind TEXT NOT NULL DEFAULT 'box',
 category TEXT NOT NULL CHECK(category IN ('wood','textile','rope')),
 location_id INTEGER REFERENCES storage_locations(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','merged','closed')),
 created_at TEXT NOT NULL,
 UNIQUE(project_id,code)
);
CREATE TABLE IF NOT EXISTS artifacts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 temp_number TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('wood','textile','rope')),
 material_note TEXT NOT NULL DEFAULT '',
 excavation_env TEXT NOT NULL DEFAULT '',
 container_id INTEGER REFERENCES containers(id) ON DELETE SET NULL,
 location_id INTEGER REFERENCES storage_locations(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered','stored','in_treatment','transferred','archived')),
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(project_id,temp_number)
);
CREATE TABLE IF NOT EXISTS custody_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
 event_type TEXT NOT NULL,
 from_container_id INTEGER,
 to_container_id INTEGER,
 from_location_id INTEGER,
 to_location_id INTEGER,
 actor_id INTEGER,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_artifact ON custody_events(artifact_id,id);
CREATE TABLE IF NOT EXISTS threshold_schemes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 category TEXT NOT NULL CHECK(category IN ('wood','textile','rope')),
 version INTEGER NOT NULL,
 config_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 UNIQUE(project_id,category,version)
);
CREATE TABLE IF NOT EXISTS sensor_batches (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 batch_key TEXT NOT NULL,
 source TEXT NOT NULL DEFAULT 'offline',
 as_of TEXT NOT NULL,
 summary_json TEXT NOT NULL DEFAULT '{}',
 imported_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 imported_at TEXT NOT NULL,
 UNIQUE(project_id,batch_key)
);
CREATE TABLE IF NOT EXISTS sensor_readings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 container_id INTEGER NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
 metric TEXT NOT NULL CHECK(metric IN ('temperature','humidity','ph','conductivity')),
 value REAL NOT NULL,
 observed_at TEXT NOT NULL,
 batch_id INTEGER NOT NULL REFERENCES sensor_batches(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL,
 UNIQUE(container_id,metric,observed_at)
);
CREATE INDEX IF NOT EXISTS idx_readings_container ON sensor_readings(container_id,metric,observed_at);
CREATE TABLE IF NOT EXISTS maintenance_windows (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 container_id INTEGER REFERENCES containers(id) ON DELETE CASCADE,
 starts_at TEXT NOT NULL,
 ends_at TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT '',
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 CHECK(ends_at > starts_at)
);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 container_id INTEGER NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
 metric TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('threshold','missing')),
 dedup_key TEXT NOT NULL UNIQUE,
 severity TEXT NOT NULL CHECK(severity IN ('warning','elevated','critical')),
 status TEXT NOT NULL CHECK(status IN ('open','acknowledged','resolved')),
 first_seen_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL,
 resolved_at TEXT NOT NULL DEFAULT '',
 details_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_project ON alerts(project_id,status,id);
CREATE TABLE IF NOT EXISTS treatment_orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
 order_type TEXT NOT NULL CHECK(order_type IN ('wet_storage','packaging','transport','lab_handover')),
 title TEXT NOT NULL,
 instructions TEXT NOT NULL DEFAULT '',
 assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','leased','done','returned','cancelled')),
 lease_owner INTEGER REFERENCES users(id) ON DELETE SET NULL,
 lease_until TEXT NOT NULL DEFAULT '',
 lease_minutes INTEGER NOT NULL DEFAULT 30,
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_project ON treatment_orders(project_id,status,id);
"""


def init_conservation_db() -> None:
    connection().executescript(CONSERVATION_SCHEMA)


def parse_ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ServiceError("invalid_timestamp", f"时间格式无效: {value}", 400) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def fmt_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _minutes(start: str, end: str) -> float:
    return (parse_ts(end) - parse_ts(start)).total_seconds() / 60.0


def _merge_intervals(windows: list[tuple[str, str]]) -> list[tuple[datetime, datetime]]:
    parsed = sorted((parse_ts(start), parse_ts(end)) for start, end in windows)
    merged: list[tuple[datetime, datetime]] = []
    for start, end in parsed:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _covered_minutes(start: datetime, end: datetime, intervals: list[tuple[datetime, datetime]]) -> float:
    total = 0.0
    for win_start, win_end in intervals:
        lo, hi = max(start, win_start), min(end, win_end)
        if lo < hi:
            total += (hi - lo).total_seconds() / 60.0
    return total


def _violates(value: float, bound: dict[str, Any]) -> bool:
    low, high = bound.get("min"), bound.get("max")
    return (low is not None and value < low) or (high is not None and value > high)


def _severity_for(duration_minutes: float, escalation: list[dict[str, Any]]) -> str:
    severity = "warning"
    for tier in escalation:
        if duration_minutes >= tier["after_minutes"]:
            severity = tier["severity"]
    return severity


def evaluate_metric_state(
    *,
    container_id: int,
    metric: str,
    readings: list[tuple[str, float]],
    config: dict[str, Any],
    windows: list[tuple[str, str]],
    as_of: str,
) -> list[dict[str, Any]]:
    """由全部历史读数重算某容器某指标的期望告警状态（纯函数，确定性）。"""
    states: list[dict[str, Any]] = []
    bound = (config.get("metrics") or {}).get(metric)
    if bound is None:
        return states
    escalation = config.get("escalation") or []
    episode: dict[str, Any] | None = None
    episodes: list[dict[str, Any]] = []
    for observed, value in readings:
        if _violates(value, bound):
            if episode is None:
                episode = {"start": observed, "last": observed, "first_value": value, "last_value": value}
            else:
                episode["last"] = observed
                episode["last_value"] = value
        elif episode is not None:
            episodes.append({**episode, "end": observed})
            episode = None
    if episode is not None:
        episodes.append({**episode, "end": None})
    for item in episodes:
        end = item["end"]
        duration = max(0.0, _minutes(item["start"], end or as_of))
        states.append({
            "kind": "threshold",
            "dedup_key": f"threshold:{container_id}:{metric}:{item['start']}",
            "severity": _severity_for(duration, escalation),
            "status": "open" if end is None else "resolved",
            "first_seen_at": item["start"],
            "last_seen_at": item["last"],
            "resolved_at": end or "",
            "details": {"min": bound.get("min"), "max": bound.get("max"), "first_value": item["first_value"], "last_value": item["last_value"]},
        })
    times = [observed for observed, _ in readings]
    if times:
        missing_after = config.get("missing_after_minutes", 180)
        intervals = _merge_intervals(windows)
        gaps: list[tuple[str, str, bool]] = [(start, end, False) for start, end in zip(times, times[1:])]
        if parse_ts(times[-1]) < parse_ts(as_of):
            gaps.append((times[-1], as_of, True))
        for gap_start, gap_end, ongoing in gaps:
            uncovered = _minutes(gap_start, gap_end) - _covered_minutes(parse_ts(gap_start), parse_ts(gap_end), intervals)
            if uncovered > missing_after:
                states.append({
                    "kind": "missing",
                    "dedup_key": f"missing:{container_id}:{metric}:{gap_start}",
                    "severity": "warning",
                    "status": "open" if ongoing else "resolved",
                    "first_seen_at": gap_start,
                    "last_seen_at": gap_end,
                    "resolved_at": "" if ongoing else gap_end,
                    "details": {"gap_start": gap_start, "missing_after_minutes": missing_after, "uncovered_minutes": round(uncovered, 2)},
                })
    return states


def normalize_scheme_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ServiceError("invalid_scheme", "阈值配置必须是对象", 400)
    raw_metrics = config.get("metrics")
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        raise ServiceError("invalid_scheme", "阈值方案至少包含一个指标", 400)
    metrics: dict[str, Any] = {}
    for name, bound in raw_metrics.items():
        if name not in METRICS:
            raise ServiceError("invalid_scheme", f"未知指标: {name}", 400)
        if not isinstance(bound, dict):
            raise ServiceError("invalid_scheme", f"指标 {name} 的阈值必须是对象", 400)
        low, high = bound.get("min"), bound.get("max")
        if low is None and high is None:
            raise ServiceError("invalid_scheme", f"指标 {name} 至少需要一个上限或下限", 400)
        for value in (low, high):
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
                raise ServiceError("invalid_scheme", f"指标 {name} 的阈值必须是有限数值", 400)
        if low is not None and high is not None and low > high:
            raise ServiceError("invalid_scheme", f"指标 {name} 的下限不能大于上限", 400)
        metrics[name] = {"min": low, "max": high}
    missing_after = config.get("missing_after_minutes", 180)
    if isinstance(missing_after, bool) or not isinstance(missing_after, int) or missing_after <= 0:
        raise ServiceError("invalid_scheme", "missing_after_minutes 必须是正整数", 400)
    escalation: list[dict[str, Any]] = []
    seen_minutes: set[int] = set()
    for tier in config.get("escalation") or []:
        after = tier.get("after_minutes")
        severity = tier.get("severity")
        if isinstance(after, bool) or not isinstance(after, int) or after <= 0:
            raise ServiceError("invalid_scheme", "升级阈值 after_minutes 必须是正整数", 400)
        if severity not in ("elevated", "critical"):
            raise ServiceError("invalid_scheme", "升级级别必须是 elevated 或 critical", 400)
        if after in seen_minutes:
            raise ServiceError("invalid_scheme", "升级阈值 after_minutes 不能重复", 400)
        seen_minutes.add(after)
        escalation.append({"after_minutes": after, "severity": severity})
    escalation.sort(key=lambda item: item["after_minutes"])
    ranks = [SEVERITY_RANK[item["severity"]] for item in escalation]
    if ranks != sorted(ranks):
        raise ServiceError("invalid_scheme", "升级级别必须随持续时间单调不减", 400)
    return {"metrics": metrics, "missing_after_minutes": missing_after, "escalation": escalation}


class ConservationService:
    def __init__(self, db: sqlite3.Connection | None = None):
        self.db = db or connection()
        self.research = ResearchService(self.db)

    # ---- 通用工具 ----
    def _role(self, project_id: int, user_id: int) -> str:
        return self.research.require_role(project_id, user_id, MEMBER_ROLES)

    def _sensitive_ids(self, db: sqlite3.Connection, project_id: int) -> set[int]:
        rows = db.execute("SELECT id FROM storage_locations WHERE project_id=? AND sensitive=1", (project_id,)).fetchall()
        return {row["id"] for row in rows}

    @staticmethod
    def _mask_location(item: dict[str, Any], sensitive_ids: set[int], role: str) -> dict[str, Any]:
        location_id = item.get("location_id")
        hidden = location_id is not None and location_id in sensitive_ids and role not in SENSITIVE_LOCATION_ROLES
        if hidden:
            item["location_id"] = None
        item["location_hidden"] = hidden
        return item

    def _require_location(self, db: sqlite3.Connection, project_id: int, location_id: int) -> sqlite3.Row:
        row = db.execute("SELECT * FROM storage_locations WHERE id=? AND project_id=?", (location_id, project_id)).fetchone()
        if row is None:
            raise ServiceError("location_not_found", "库位不存在", 404)
        return row

    def _require_container(self, db: sqlite3.Connection, project_id: int, container_id: int) -> sqlite3.Row:
        row = db.execute("SELECT * FROM containers WHERE id=? AND project_id=?", (container_id, project_id)).fetchone()
        if row is None:
            raise ServiceError("container_not_found", "容器不存在", 404)
        return row

    def _resolve_container(self, db: sqlite3.Connection, project_id: int, item: dict[str, Any]) -> sqlite3.Row:
        if item.get("container_id") is not None:
            return self._require_container(db, project_id, item["container_id"])
        row = db.execute("SELECT * FROM containers WHERE project_id=? AND code=?", (project_id, item.get("container_code"))).fetchone()
        if row is None:
            raise ServiceError("container_not_found", f"读数引用的容器不存在: {item.get('container_code')}", 404)
        return row

    def _custody(self, db: sqlite3.Connection, project_id: int, artifact_id: int, event_type: str, from_container: int | None, to_container: int | None, from_location: int | None, to_location: int | None, actor_id: int | None, note: str, at: str) -> None:
        db.execute(
            "INSERT INTO custody_events(project_id,artifact_id,event_type,from_container_id,to_container_id,from_location_id,to_location_id,actor_id,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project_id, artifact_id, event_type, from_container, to_container, from_location, to_location, actor_id, note, at),
        )

    def _artifact_public(self, db: sqlite3.Connection, project_id: int, artifact_id: int, role: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT a.*, c.code AS container_code FROM artifacts a LEFT JOIN containers c ON c.id=a.container_id WHERE a.id=? AND a.project_id=?",
            (artifact_id, project_id),
        ).fetchone()
        if row is None:
            raise ServiceError("artifact_not_found", "遗物不存在", 404)
        return self._mask_location(dict(row), self._sensitive_ids(db, project_id), role)

    # ---- 库位 ----
    def create_location(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], REGISTRAR_ROLES)
        at = at or now()
        try:
            with transaction(immediate=True) as db:
                cursor = db.execute(
                    "INSERT INTO storage_locations(project_id,code,name,sensitive,created_at) VALUES(?,?,?,?,?)",
                    (project_id, payload["code"], payload["name"], 1 if payload.get("sensitive") else 0, at),
                )
                self.research.audit("location.create", "storage_location", str(cursor.lastrowid), payload, project_id=project_id, actor_id=actor["id"])
                row = dict(db.execute("SELECT * FROM storage_locations WHERE id=?", (cursor.lastrowid,)).fetchone())
                row["sensitive"] = bool(row["sensitive"])
                return row
        except sqlite3.IntegrityError as exc:
            raise ServiceError("location_exists", "库位编码已存在", 409) from exc

    def list_locations(self, project_id: int, actor: Any) -> dict[str, Any]:
        role = self._role(project_id, actor["id"])
        rows = self.db.execute("SELECT * FROM storage_locations WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
        data = []
        for row in rows:
            item = dict(row)
            item["sensitive"] = bool(item["sensitive"])
            if item["sensitive"] and role not in SENSITIVE_LOCATION_ROLES:
                item["code"] = None
                item["name"] = None
                item["hidden"] = True
            else:
                item["hidden"] = False
            data.append(item)
        return {"data": data}

    # ---- 容器 ----
    def create_container(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], REGISTRAR_ROLES)
        at = at or now()
        category = payload.get("category")
        if category not in CATEGORIES:
            raise ServiceError("invalid_category", "遗物类别无效", 400)
        try:
            with transaction(immediate=True) as db:
                location_id = payload.get("location_id")
                if location_id is not None:
                    self._require_location(db, project_id, location_id)
                cursor = db.execute(
                    "INSERT INTO containers(project_id,code,kind,category,location_id,created_at) VALUES(?,?,?,?,?,?)",
                    (project_id, payload["code"], payload.get("kind") or "box", category, location_id, at),
                )
                self.research.audit("container.create", "container", str(cursor.lastrowid), payload, project_id=project_id, actor_id=actor["id"])
                return dict(db.execute("SELECT * FROM containers WHERE id=?", (cursor.lastrowid,)).fetchone())
        except sqlite3.IntegrityError as exc:
            raise ServiceError("container_exists", "容器编码已存在", 409) from exc

    def list_containers(self, project_id: int, actor: Any) -> dict[str, Any]:
        role = self._role(project_id, actor["id"])
        rows = self.db.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM artifacts a WHERE a.container_id=c.id) AS artifact_count FROM containers c WHERE c.project_id=? ORDER BY c.id",
            (project_id,),
        ).fetchall()
        sensitive = self._sensitive_ids(self.db, project_id)
        return {"data": [self._mask_location(dict(row), sensitive, role) for row in rows]}

    # ---- 遗物登记 ----
    def register_artifact(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        role = self.research.require_role(project_id, actor["id"], REGISTRAR_ROLES)
        at = at or now()
        category = payload.get("category")
        if category not in CATEGORIES:
            raise ServiceError("invalid_category", "遗物类别无效", 400)
        with transaction(immediate=True) as db:
            container = None
            if payload.get("container_code"):
                container = db.execute("SELECT * FROM containers WHERE project_id=? AND code=?", (project_id, payload["container_code"])).fetchone()
                if container is None:
                    raise ServiceError("container_not_found", "容器不存在", 404)
                if container["status"] != "active":
                    raise ServiceError("container_not_active", "容器已停用，不能放入遗物", 409)
                if container["category"] != category:
                    raise ServiceError("category_mismatch", "遗物类别与容器类别不一致", 400)
            location_id = container["location_id"] if container else payload.get("location_id")
            if location_id is not None:
                self._require_location(db, project_id, location_id)
            status = "stored" if container else "registered"
            try:
                cursor = db.execute(
                    "INSERT INTO artifacts(project_id,temp_number,category,material_note,excavation_env,container_id,location_id,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (project_id, payload["temp_number"], category, payload.get("material_note", ""), payload.get("excavation_env", ""), container["id"] if container else None, location_id, status, actor["id"], at, at),
                )
            except sqlite3.IntegrityError as exc:
                raise ServiceError("artifact_exists", "临时编号已存在", 409) from exc
            artifact_id = cursor.lastrowid
            self._custody(db, project_id, artifact_id, "register", None, container["id"] if container else None, None, location_id, actor["id"], payload.get("note", ""), at)
            self.research.audit("artifact.register", "artifact", str(artifact_id), payload, project_id=project_id, actor_id=actor["id"])
            return self._artifact_public(db, project_id, artifact_id, role)

    def list_artifacts(self, project_id: int, actor: Any) -> dict[str, Any]:
        role = self._role(project_id, actor["id"])
        rows = self.db.execute(
            "SELECT a.*, c.code AS container_code FROM artifacts a LEFT JOIN containers c ON c.id=a.container_id WHERE a.project_id=? ORDER BY a.id",
            (project_id,),
        ).fetchall()
        sensitive = self._sensitive_ids(self.db, project_id)
        return {"data": [self._mask_location(dict(row), sensitive, role) for row in rows]}

    def get_artifact(self, project_id: int, actor: Any, artifact_id: int) -> dict[str, Any]:
        role = self._role(project_id, actor["id"])
        return self._artifact_public(self.db, project_id, artifact_id, role)

    def artifact_custody(self, project_id: int, actor: Any, artifact_id: int) -> dict[str, Any]:
        role = self._role(project_id, actor["id"])
        artifact = self._artifact_public(self.db, project_id, artifact_id, role)
        rows = self.db.execute("SELECT * FROM custody_events WHERE artifact_id=? ORDER BY id", (artifact_id,)).fetchall()
        sensitive = self._sensitive_ids(self.db, project_id)
        events = []
        for row in rows:
            item = dict(row)
            hidden = False
            for field in ("from_location_id", "to_location_id"):
                if item[field] is not None and item[field] in sensitive and role not in SENSITIVE_LOCATION_ROLES:
                    item[field] = None
                    hidden = True
            item["locations_hidden"] = hidden
            events.append(item)
        return {"artifact": artifact, "events": events}

    # ---- 包装合并与拆分 ----
    def merge_containers(self, project_id: int, actor: Any, target_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        role = self.research.require_role(project_id, actor["id"], OPERATOR_ROLES)
        at = at or now()
        source_ids = payload.get("source_container_ids") or []
        note = payload.get("note", "")
        with transaction(immediate=True) as db:
            target = self._require_container(db, project_id, target_id)
            if target["status"] != "active":
                raise ServiceError("container_not_active", "目标容器已停用", 409)
            sources: list[sqlite3.Row] = []
            seen: set[int] = set()
            for source_id in source_ids:
                if source_id == target_id:
                    raise ServiceError("invalid_merge", "容器不能合并到自身", 400)
                if source_id in seen:
                    raise ServiceError("invalid_merge", "来源容器重复", 400)
                seen.add(source_id)
                source = self._require_container(db, project_id, source_id)
                if source["status"] != "active":
                    raise ServiceError("container_not_active", f"来源容器 {source['code']} 已停用", 409)
                if source["category"] != target["category"]:
                    raise ServiceError("category_mismatch", "来源容器与目标容器类别不一致", 400)
                sources.append(source)
            moved = 0
            for source in sources:
                artifacts = db.execute("SELECT * FROM artifacts WHERE container_id=? ORDER BY id", (source["id"],)).fetchall()
                for artifact in artifacts:
                    db.execute("UPDATE artifacts SET container_id=?, location_id=?, updated_at=? WHERE id=?", (target["id"], target["location_id"], at, artifact["id"]))
                    self._custody(db, project_id, artifact["id"], "merge", source["id"], target["id"], artifact["location_id"], target["location_id"], actor["id"], note, at)
                    moved += 1
                db.execute("UPDATE containers SET status='merged' WHERE id=?", (source["id"],))
            self.research.audit("container.merge", "container", str(target_id), {"sources": source_ids, "note": note, "moved": moved}, project_id=project_id, actor_id=actor["id"])
            return {"target_id": target_id, "sources": source_ids, "moved": moved}

    def split_container(self, project_id: int, actor: Any, source_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        role = self.research.require_role(project_id, actor["id"], OPERATOR_ROLES)
        at = at or now()
        artifact_ids = payload.get("artifact_ids") or []
        spec = payload.get("new_container") or {}
        note = payload.get("note", "")
        with transaction(immediate=True) as db:
            source = self._require_container(db, project_id, source_id)
            if source["status"] != "active":
                raise ServiceError("container_not_active", "来源容器已停用", 409)
            if not artifact_ids:
                raise ServiceError("invalid_split", "拆分必须指定至少一件遗物", 400)
            location_id = spec.get("location_id", source["location_id"])
            if location_id is not None:
                self._require_location(db, project_id, location_id)
            try:
                cursor = db.execute(
                    "INSERT INTO containers(project_id,code,kind,category,location_id,created_at) VALUES(?,?,?,?,?,?)",
                    (project_id, spec["code"], spec.get("kind") or "box", source["category"], location_id, at),
                )
            except sqlite3.IntegrityError as exc:
                raise ServiceError("container_exists", "新容器编码已存在", 409) from exc
            new_container_id = cursor.lastrowid
            moved = 0
            for artifact_id in artifact_ids:
                artifact = db.execute("SELECT * FROM artifacts WHERE id=? AND project_id=?", (artifact_id, project_id)).fetchone()
                if artifact is None:
                    raise ServiceError("artifact_not_found", f"遗物不存在: {artifact_id}", 404)
                if artifact["container_id"] != source_id:
                    raise ServiceError("artifact_not_in_container", f"遗物 {artifact['temp_number']} 不在来源容器中", 400)
                db.execute("UPDATE artifacts SET container_id=?, location_id=?, updated_at=? WHERE id=?", (new_container_id, location_id, at, artifact_id))
                self._custody(db, project_id, artifact_id, "split", source_id, new_container_id, artifact["location_id"], location_id, actor["id"], note, at)
                moved += 1
            self.research.audit("container.split", "container", str(new_container_id), {"source": source_id, "artifact_ids": artifact_ids, "note": note, "moved": moved}, project_id=project_id, actor_id=actor["id"])
            return {"source_id": source_id, "new_container_id": new_container_id, "moved": moved}

    # ---- 阈值方案（可版本化） ----
    def publish_threshold(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], LEAD_ROLES)
        at = at or now()
        category = payload.get("category")
        if category not in CATEGORIES:
            raise ServiceError("invalid_category", "遗物类别无效", 400)
        config = normalize_scheme_config(payload.get("config") or {})
        with transaction(immediate=True) as db:
            row = db.execute("SELECT COALESCE(MAX(version),0) AS v FROM threshold_schemes WHERE project_id=? AND category=?", (project_id, category)).fetchone()
            version = row["v"] + 1
            db.execute("UPDATE threshold_schemes SET status='retired' WHERE project_id=? AND category=? AND status='active'", (project_id, category))
            cursor = db.execute(
                "INSERT INTO threshold_schemes(project_id,category,version,config_json,status,created_by,created_at) VALUES(?,?,?,?,'active',?,?)",
                (project_id, category, version, stable_json(config), actor["id"], at),
            )
            self.research.audit("threshold.publish", "threshold_scheme", str(cursor.lastrowid), {"category": category, "version": version, "config": config}, project_id=project_id, actor_id=actor["id"])
            return self._scheme_public(dict(db.execute("SELECT * FROM threshold_schemes WHERE id=?", (cursor.lastrowid,)).fetchone()))

    @staticmethod
    def _scheme_public(row: dict[str, Any]) -> dict[str, Any]:
        row = dict(row)
        row["config"] = json.loads(row.pop("config_json"))
        return row

    def list_thresholds(self, project_id: int, actor: Any) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        rows = self.db.execute("SELECT * FROM threshold_schemes WHERE project_id=? ORDER BY category, version DESC", (project_id,)).fetchall()
        return {"data": [self._scheme_public(dict(row)) for row in rows]}

    def _active_scheme(self, db: sqlite3.Connection, project_id: int, category: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT * FROM threshold_schemes WHERE project_id=? AND category=? AND status='active' ORDER BY version DESC LIMIT 1",
            (project_id, category),
        ).fetchone()

    # ---- 维护窗口 ----
    def create_window(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], STAFF_ROLES)
        at = at or now()
        starts_at = fmt_ts(parse_ts(payload["starts_at"]))
        ends_at = fmt_ts(parse_ts(payload["ends_at"]))
        if parse_ts(ends_at) <= parse_ts(starts_at):
            raise ServiceError("invalid_window", "维护窗口结束时间必须晚于开始时间", 400)
        with transaction(immediate=True) as db:
            container_id = payload.get("container_id")
            if container_id is not None:
                self._require_container(db, project_id, container_id)
            cursor = db.execute(
                "INSERT INTO maintenance_windows(project_id,container_id,starts_at,ends_at,reason,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (project_id, container_id, starts_at, ends_at, payload.get("reason", ""), actor["id"], at),
            )
            self.research.audit("window.create", "maintenance_window", str(cursor.lastrowid), {"container_id": container_id, "starts_at": starts_at, "ends_at": ends_at, "reason": payload.get("reason", "")}, project_id=project_id, actor_id=actor["id"])
            return dict(db.execute("SELECT * FROM maintenance_windows WHERE id=?", (cursor.lastrowid,)).fetchone())

    def list_windows(self, project_id: int, actor: Any) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        rows = self.db.execute("SELECT * FROM maintenance_windows WHERE project_id=? ORDER BY starts_at, id", (project_id,)).fetchall()
        return {"data": [dict(row) for row in rows]}

    def _windows_for(self, db: sqlite3.Connection, project_id: int, container_id: int) -> list[tuple[str, str]]:
        rows = db.execute(
            "SELECT starts_at, ends_at FROM maintenance_windows WHERE project_id=? AND (container_id IS NULL OR container_id=?)",
            (project_id, container_id),
        ).fetchall()
        return [(row["starts_at"], row["ends_at"]) for row in rows]

    # ---- 告警重算 ----
    @staticmethod
    def _empty_events() -> dict[str, list[dict[str, Any]]]:
        return {"opened": [], "escalated": [], "resolved": [], "reopened": [], "retracted": []}

    def _reconcile(self, db: sqlite3.Connection, project_id: int, container: sqlite3.Row, metric: str, as_of: str, actor_id: int | None, at: str) -> dict[str, list[dict[str, Any]]]:
        """把某容器某指标的告警表状态对齐到由全部读数重算出的期望状态。"""
        events = self._empty_events()
        scheme = self._active_scheme(db, project_id, container["category"])
        if scheme is None:
            return events
        config = json.loads(scheme["config_json"])
        rows = db.execute("SELECT observed_at, value FROM sensor_readings WHERE container_id=? AND metric=? ORDER BY observed_at", (container["id"], metric)).fetchall()
        readings = [(row["observed_at"], row["value"]) for row in rows]
        windows = self._windows_for(db, project_id, container["id"])
        desired = evaluate_metric_state(container_id=container["id"], metric=metric, readings=readings, config=config, windows=windows, as_of=as_of)
        existing = {
            row["dedup_key"]: row
            for row in db.execute("SELECT * FROM alerts WHERE container_id=? AND metric=?", (container["id"], metric)).fetchall()
        }
        base = {"container_id": container["id"], "container_code": container["code"], "metric": metric}
        desired_keys = {state["dedup_key"] for state in desired}
        for key, row in existing.items():
            if key not in desired_keys:
                db.execute("DELETE FROM alerts WHERE id=?", (row["id"],))
                self.research.audit("alert.retract", "alert", str(row["id"]), {**base, "dedup_key": key, "kind": row["kind"], "reason": "episode_changed"}, project_id=project_id, actor_id=actor_id)
                events["retracted"].append({**base, "alert_id": row["id"], "kind": row["kind"], "dedup_key": key})
        for state in desired:
            row = existing.get(state["dedup_key"])
            item = {**base, "kind": state["kind"], "severity": state["severity"], "first_seen_at": state["first_seen_at"], "dedup_key": state["dedup_key"]}
            if row is None:
                cursor = db.execute(
                    "INSERT INTO alerts(project_id,container_id,metric,kind,dedup_key,severity,status,first_seen_at,last_seen_at,resolved_at,details_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (project_id, container["id"], metric, state["kind"], state["dedup_key"], state["severity"], state["status"], state["first_seen_at"], state["last_seen_at"], state["resolved_at"], stable_json(state["details"]), at, at),
                )
                item["alert_id"] = cursor.lastrowid
                self.research.audit("alert.open", "alert", str(cursor.lastrowid), {**item, "status": state["status"], "resolved_at": state["resolved_at"]}, project_id=project_id, actor_id=actor_id)
                events["opened"].append(item)
                continue
            item["alert_id"] = row["id"]
            severity = row["severity"]
            if SEVERITY_RANK[state["severity"]] > SEVERITY_RANK[row["severity"]]:
                severity = state["severity"]
                self.research.audit("alert.escalate", "alert", str(row["id"]), {**base, "dedup_key": state["dedup_key"], "from": row["severity"], "to": severity}, project_id=project_id, actor_id=actor_id)
                events["escalated"].append({**item, "from": row["severity"], "to": severity})
            status = row["status"]
            resolved_at = row["resolved_at"]
            if state["status"] == "resolved" and status in ("open", "acknowledged"):
                status, resolved_at = "resolved", state["resolved_at"]
                self.research.audit("alert.resolve", "alert", str(row["id"]), {**base, "dedup_key": state["dedup_key"], "resolved_at": resolved_at}, project_id=project_id, actor_id=actor_id)
                events["resolved"].append(item)
            elif state["status"] == "open" and status == "resolved":
                status, resolved_at = "open", ""
                self.research.audit("alert.reopen", "alert", str(row["id"]), {**base, "dedup_key": state["dedup_key"]}, project_id=project_id, actor_id=actor_id)
                events["reopened"].append(item)
            elif state["status"] == "resolved" and state["resolved_at"] != resolved_at:
                resolved_at = state["resolved_at"]
            if (severity, status, resolved_at, state["last_seen_at"]) != (row["severity"], row["status"], row["resolved_at"], row["last_seen_at"]):
                db.execute(
                    "UPDATE alerts SET severity=?, status=?, last_seen_at=?, resolved_at=?, details_json=?, updated_at=? WHERE id=?",
                    (severity, status, state["last_seen_at"], resolved_at, stable_json(state["details"]), at, row["id"]),
                )
        return events

    @staticmethod
    def _merge_events(total: dict[str, list[dict[str, Any]]], part: dict[str, list[dict[str, Any]]]) -> None:
        for key, items in part.items():
            total[key].extend(items)

    @staticmethod
    def _sort_events(events: dict[str, list[dict[str, Any]]]) -> None:
        for items in events.values():
            items.sort(key=lambda item: (item.get("container_code") or "", item.get("metric") or "", item.get("kind") or "", item.get("first_seen_at") or ""))

    # ---- 离线批次导入 ----
    def import_batch(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], OPERATOR_ROLES)
        at = at or now()
        batch_key = payload["batch_key"]
        old = self.db.execute("SELECT * FROM sensor_batches WHERE project_id=? AND batch_key=?", (project_id, batch_key)).fetchone()
        if old is not None:
            summary = json.loads(old["summary_json"])
            summary["duplicate"] = True
            return summary
        try:
            return self._import_batch_tx(project_id, actor, payload, batch_key, at)
        except sqlite3.IntegrityError:
            # 并发重复批次：唯一约束冲突后回滚，返回首次导入的摘要
            old = self.db.execute("SELECT * FROM sensor_batches WHERE project_id=? AND batch_key=?", (project_id, batch_key)).fetchone()
            if old is not None:
                summary = json.loads(old["summary_json"])
                summary["duplicate"] = True
                return summary
            raise

    def _import_batch_tx(self, project_id: int, actor: Any, payload: dict[str, Any], batch_key: str, at: str) -> dict[str, Any]:
        with transaction(immediate=True) as db:
            normalized: list[tuple[sqlite3.Row, str, float, str]] = []
            for item in payload.get("readings") or []:
                container = self._resolve_container(db, project_id, item)
                value = float(item["value"])
                if not math.isfinite(value):
                    raise ServiceError("invalid_reading", "读数值必须是有限数值", 400)
                normalized.append((container, item["metric"], value, fmt_ts(parse_ts(item["observed_at"]))))
            if payload.get("as_of"):
                as_of = fmt_ts(parse_ts(payload["as_of"]))
            elif normalized:
                as_of = max(entry[3] for entry in normalized)
            else:
                as_of = at
            cursor = db.execute(
                "INSERT INTO sensor_batches(project_id,batch_key,source,as_of,imported_by,imported_at) VALUES(?,?,?,?,?,?)",
                (project_id, batch_key, payload.get("source") or "offline", as_of, actor["id"], at),
            )
            batch_id = cursor.lastrowid
            imported = duplicates = 0
            affected: set[tuple[int, str]] = set()
            containers: dict[int, sqlite3.Row] = {}
            for container, metric, value, observed in normalized:
                result = db.execute(
                    "INSERT OR IGNORE INTO sensor_readings(project_id,container_id,metric,value,observed_at,batch_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (project_id, container["id"], metric, value, observed, batch_id, at),
                )
                if result.rowcount:
                    imported += 1
                    affected.add((container["id"], metric))
                    containers[container["id"]] = container
                else:
                    duplicates += 1
            events = self._empty_events()
            for container_id, metric in sorted(affected):
                self._merge_events(events, self._reconcile(db, project_id, containers[container_id], metric, as_of, actor["id"], at))
            self._sort_events(events)
            todos = self.todo_summary(project_id, as_of, db=db)
            summary = {"batch_id": batch_id, "batch_key": batch_key, "duplicate": False, "imported": imported, "duplicates": duplicates, "as_of": as_of, "alerts": events, "todos": todos}
            db.execute("UPDATE sensor_batches SET summary_json=? WHERE id=?", (stable_json(summary), batch_id))
            self.research.audit("batch.import", "sensor_batch", str(batch_id), {"batch_key": batch_key, "imported": imported, "duplicates": duplicates, "as_of": as_of}, project_id=project_id, actor_id=actor["id"])
            return summary

    def list_batches(self, project_id: int, actor: Any) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        rows = self.db.execute(
            "SELECT b.*, (SELECT COUNT(*) FROM sensor_readings r WHERE r.batch_id=b.id) AS reading_count FROM sensor_batches b WHERE b.project_id=? ORDER BY b.id",
            (project_id,),
        ).fetchall()
        data = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item.pop("summary_json"))
            data.append(item)
        return {"data": data}

    # ---- 全量评估（升级推进与缺测检测的周期入口） ----
    def evaluate_all(self, project_id: int, actor: Any, as_of: str | None = None, at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], STAFF_ROLES)
        at = at or now()
        as_of = fmt_ts(parse_ts(as_of)) if as_of else at
        with transaction(immediate=True) as db:
            pairs = db.execute("SELECT DISTINCT container_id, metric FROM sensor_readings WHERE project_id=? ORDER BY container_id, metric", (project_id,)).fetchall()
            events = self._empty_events()
            for pair in pairs:
                container = self._require_container(db, project_id, pair["container_id"])
                self._merge_events(events, self._reconcile(db, project_id, container, pair["metric"], as_of, actor["id"], at))
            self._sort_events(events)
            return {"as_of": as_of, "alerts": events, "todos": self.todo_summary(project_id, as_of, db=db)}

    # ---- 离线重放（只读，确定性） ----
    def replay(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], STAFF_ROLES)
        at = at or now()
        as_of = fmt_ts(parse_ts(payload["as_of"])) if payload.get("as_of") else at
        provided: dict[tuple[int, str], list[tuple[str, float]]] = {}
        containers: dict[int, sqlite3.Row] = {}
        for item in payload.get("readings") or []:
            container = self._resolve_container(self.db, project_id, item)
            value = float(item["value"])
            if not math.isfinite(value):
                raise ServiceError("invalid_reading", "读数值必须是有限数值", 400)
            provided.setdefault((container["id"], item["metric"]), []).append((fmt_ts(parse_ts(item["observed_at"])), value))
            containers[container["id"]] = container
        results: list[dict[str, Any]] = []
        for container_id, metric in sorted(provided):
            container = containers[container_id]
            scheme = self._active_scheme(self.db, project_id, container["category"])
            if scheme is None:
                continue
            config = json.loads(scheme["config_json"])
            stored = [
                (row["observed_at"], row["value"])
                for row in self.db.execute("SELECT observed_at, value FROM sensor_readings WHERE container_id=? AND metric=? ORDER BY observed_at", (container_id, metric)).fetchall()
            ]
            merged: dict[str, float] = {}
            for observed, value in stored + provided[(container_id, metric)]:
                merged.setdefault(observed, value)
            readings = sorted(merged.items())
            windows = self._windows_for(self.db, project_id, container_id)
            for state in evaluate_metric_state(container_id=container_id, metric=metric, readings=readings, config=config, windows=windows, as_of=as_of):
                results.append({"container_id": container_id, "container_code": container["code"], "metric": metric, **state})
        results.sort(key=lambda item: (item["container_code"], item["metric"], item["kind"], item["first_seen_at"]))
        open_states = [state for state in results if state["status"] == "open"]
        by_severity: dict[str, int] = {}
        for state in open_states:
            by_severity[state["severity"]] = by_severity.get(state["severity"], 0) + 1
        orders = self.todo_summary(project_id, as_of)["orders"]
        return {"as_of": as_of, "alerts": results, "todos": {"alerts": {"open": len(open_states), "by_severity": by_severity, "items": open_states}, "orders": orders}}

    # ---- 告警查询与确认 ----
    def list_alerts(self, project_id: int, actor: Any, status: str | None = None) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        sql = "SELECT a.*, c.code AS container_code, c.category AS container_category FROM alerts a JOIN containers c ON c.id=a.container_id WHERE a.project_id=?"
        params: list[Any] = [project_id]
        if status:
            sql += " AND a.status=?"
            params.append(status)
        sql += " ORDER BY a.id"
        rows = self.db.execute(sql, params).fetchall()
        data = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            data.append(item)
        return {"data": data}

    def acknowledge_alert(self, project_id: int, actor: Any, alert_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], STAFF_ROLES)
        at = at or now()
        with transaction(immediate=True) as db:
            row = db.execute("SELECT * FROM alerts WHERE id=? AND project_id=?", (alert_id, project_id)).fetchone()
            if row is None:
                raise ServiceError("alert_not_found", "告警不存在", 404)
            if row["status"] != "open":
                raise ServiceError("alert_not_open", "只有未处理的告警可以确认", 409)
            db.execute("UPDATE alerts SET status='acknowledged', updated_at=? WHERE id=?", (at, alert_id))
            self.research.audit("alert.acknowledge", "alert", str(alert_id), {"note": payload.get("note", "")}, project_id=project_id, actor_id=actor["id"])
            return dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())

    # ---- 待办摘要 ----
    def todos(self, project_id: int, actor: Any, as_of: str | None = None) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        stamp = fmt_ts(parse_ts(as_of)) if as_of else now()
        return self.todo_summary(project_id, stamp)

    def todo_summary(self, project_id: int, as_of: str, db: sqlite3.Connection | None = None) -> dict[str, Any]:
        db = db or self.db
        alert_rows = db.execute(
            "SELECT a.*, c.code AS container_code FROM alerts a JOIN containers c ON c.id=a.container_id WHERE a.project_id=? AND a.status IN ('open','acknowledged') ORDER BY a.id",
            (project_id,),
        ).fetchall()
        alert_items = []
        by_severity: dict[str, int] = {}
        for row in alert_rows:
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
            alert_items.append({
                "id": row["id"],
                "container_code": row["container_code"],
                "metric": row["metric"],
                "kind": row["kind"],
                "severity": row["severity"],
                "status": row["status"],
                "first_seen_at": row["first_seen_at"],
                "duration_minutes": round(max(0.0, _minutes(row["first_seen_at"], as_of)), 1),
            })
        order_rows = db.execute(
            "SELECT o.*, a.temp_number FROM treatment_orders o JOIN artifacts a ON a.id=o.artifact_id WHERE o.project_id=? AND o.status IN ('open','leased') ORDER BY o.id",
            (project_id,),
        ).fetchall()
        order_items = []
        expired = 0
        for row in order_rows:
            lease_expired = row["status"] == "leased" and row["lease_until"] < as_of
            expired += 1 if lease_expired else 0
            order_items.append({
                "id": row["id"],
                "temp_number": row["temp_number"],
                "order_type": row["order_type"],
                "status": row["status"],
                "assignee_id": row["assignee_id"],
                "lease_until": row["lease_until"],
                "lease_expired": lease_expired,
            })
        return {
            "project_id": project_id,
            "as_of": as_of,
            "alerts": {
                "open": sum(1 for row in alert_rows if row["status"] == "open"),
                "acknowledged": sum(1 for row in alert_rows if row["status"] == "acknowledged"),
                "by_severity": by_severity,
                "items": alert_items,
            },
            "orders": {
                "open": sum(1 for row in order_rows if row["status"] == "open"),
                "leased": sum(1 for row in order_rows if row["status"] == "leased"),
                "lease_expired": expired,
                "items": order_items,
            },
        }

    # ---- 处置单 ----
    def _require_conservator(self, db: sqlite3.Connection, project_id: int, user_id: int) -> None:
        row = db.execute("SELECT role FROM project_members WHERE project_id=? AND user_id=?", (project_id, user_id)).fetchone()
        if row is None or row["role"] != "conservator":
            raise ServiceError("assignee_not_conservator", "处置单只能指派给项目保护人员(conservator)", 400)

    def _get_order(self, db: sqlite3.Connection, project_id: int, order_id: int) -> sqlite3.Row:
        row = db.execute("SELECT * FROM treatment_orders WHERE id=? AND project_id=?", (order_id, project_id)).fetchone()
        if row is None:
            raise ServiceError("order_not_found", "处置单不存在", 404)
        return row

    def _order_public(self, db: sqlite3.Connection, project_id: int, order_id: int, at: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT o.*, a.temp_number, u.display_name AS assignee_name FROM treatment_orders o JOIN artifacts a ON a.id=o.artifact_id LEFT JOIN users u ON u.id=o.assignee_id WHERE o.id=? AND o.project_id=?",
            (order_id, project_id),
        ).fetchone()
        item = dict(row)
        item["lease_expired"] = item["status"] == "leased" and item["lease_until"] < at
        return item

    def _set_artifact_status(self, db: sqlite3.Connection, project_id: int, artifact_id: int, status: str, actor_id: int | None, note: str, at: str, event_type: str = "status") -> None:
        db.execute("UPDATE artifacts SET status=?, updated_at=? WHERE id=?", (status, at, artifact_id))
        self._custody(db, project_id, artifact_id, event_type, None, None, None, None, actor_id, note, at)

    def create_order(self, project_id: int, actor: Any, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], LEAD_ROLES)
        at = at or now()
        if payload.get("order_type") not in ORDER_TYPES:
            raise ServiceError("invalid_order_type", "处置单类型无效", 400)
        with transaction(immediate=True) as db:
            artifact = db.execute("SELECT * FROM artifacts WHERE id=? AND project_id=?", (payload["artifact_id"], project_id)).fetchone()
            if artifact is None:
                raise ServiceError("artifact_not_found", "遗物不存在", 404)
            self._require_conservator(db, project_id, payload["assignee_id"])
            existing = db.execute("SELECT id FROM treatment_orders WHERE artifact_id=? AND status IN ('open','leased')", (artifact["id"],)).fetchone()
            if existing is not None:
                raise ServiceError("order_exists", "该遗物已有进行中的处置单", 409)
            cursor = db.execute(
                "INSERT INTO treatment_orders(project_id,artifact_id,order_type,title,instructions,assignee_id,lease_minutes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (project_id, artifact["id"], payload["order_type"], payload["title"], payload.get("instructions", ""), payload["assignee_id"], payload.get("lease_minutes") or 30, actor["id"], at, at),
            )
            self.research.audit("order.create", "treatment_order", str(cursor.lastrowid), {"artifact_id": artifact["id"], "order_type": payload["order_type"], "assignee_id": payload["assignee_id"]}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, cursor.lastrowid, at)

    def list_orders(self, project_id: int, actor: Any, status: str | None = None, at: str | None = None) -> dict[str, Any]:
        self._role(project_id, actor["id"])
        at = at or now()
        sql = "SELECT o.*, a.temp_number, u.display_name AS assignee_name FROM treatment_orders o JOIN artifacts a ON a.id=o.artifact_id LEFT JOIN users u ON u.id=o.assignee_id WHERE o.project_id=?"
        params: list[Any] = [project_id]
        if status:
            sql += " AND o.status=?"
            params.append(status)
        sql += " ORDER BY o.id"
        rows = self.db.execute(sql, params).fetchall()
        data = []
        for row in rows:
            item = dict(row)
            item["lease_expired"] = item["status"] == "leased" and item["lease_until"] < at
            data.append(item)
        return {"data": data}

    def claim_order(self, project_id: int, actor: Any, order_id: int, at: str | None = None) -> dict[str, Any]:
        at = at or now()
        with transaction(immediate=True) as db:
            self._recover_project_leases(db, project_id, at)
            order = self._get_order(db, project_id, order_id)
            if order["status"] != "open":
                raise ServiceError("order_not_open", "处置单当前不可领取", 409)
            if order["assignee_id"] != actor["id"]:
                raise ServiceError("not_assignee", "只有指定保护人员可领取处置单", 403)
            lease_until = fmt_ts(parse_ts(at) + timedelta(minutes=order["lease_minutes"]))
            db.execute("UPDATE treatment_orders SET status='leased', lease_owner=?, lease_until=?, updated_at=? WHERE id=?", (actor["id"], lease_until, at, order_id))
            self._set_artifact_status(db, project_id, order["artifact_id"], "in_treatment", actor["id"], f"处置单 {order_id} 领取", at)
            self.research.audit("order.claim", "treatment_order", str(order_id), {"lease_until": lease_until}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, order_id, at)

    def transfer_order(self, project_id: int, actor: Any, order_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        at = at or now()
        new_assignee = payload["assignee_id"]
        with transaction(immediate=True) as db:
            self._recover_project_leases(db, project_id, at)
            order = self._get_order(db, project_id, order_id)
            if order["status"] in ("done", "cancelled"):
                raise ServiceError("order_closed", "处置单已关闭，不能转交", 409)
            role = self._role(project_id, actor["id"])
            is_holder = order["status"] == "leased" and order["lease_owner"] == actor["id"]
            is_assignee = order["status"] == "open" and order["assignee_id"] == actor["id"]
            if not (is_holder or is_assignee or role in LEAD_ROLES):
                raise ServiceError("forbidden", "只有租约持有人、当前被指派人或项目负责人可以转交", 403)
            self._require_conservator(db, project_id, new_assignee)
            db.execute("UPDATE treatment_orders SET status='open', assignee_id=?, lease_owner=NULL, lease_until='', updated_at=? WHERE id=?", (new_assignee, at, order_id))
            self.research.audit("order.transfer", "treatment_order", str(order_id), {"from_assignee": order["assignee_id"], "to_assignee": new_assignee}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, order_id, at)

    def complete_order(self, project_id: int, actor: Any, order_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        at = at or now()
        with transaction(immediate=True) as db:
            self._recover_project_leases(db, project_id, at)
            order = self._get_order(db, project_id, order_id)
            if order["status"] != "leased" or order["lease_owner"] != actor["id"]:
                raise ServiceError("order_not_owned", "只有租约持有人可以完成处置单", 409)
            db.execute("UPDATE treatment_orders SET status='done', lease_owner=NULL, lease_until='', updated_at=? WHERE id=?", (at, order_id))
            new_status = ORDER_RESULT_STATUS[order["order_type"]]
            self._set_artifact_status(db, project_id, order["artifact_id"], new_status, actor["id"], f"处置单 {order_id}({order['order_type']}) 完成", at, event_type="treatment")
            self.research.audit("order.complete", "treatment_order", str(order_id), {"note": payload.get("note", ""), "artifact_status": new_status}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, order_id, at)

    def return_order(self, project_id: int, actor: Any, order_id: int, payload: dict[str, Any], at: str | None = None) -> dict[str, Any]:
        at = at or now()
        reason = (payload.get("reason") or "").strip()
        if not reason:
            raise ServiceError("reason_required", "退回处置单必须填写原因", 400)
        with transaction(immediate=True) as db:
            self._recover_project_leases(db, project_id, at)
            order = self._get_order(db, project_id, order_id)
            if order["status"] != "leased" or order["lease_owner"] != actor["id"]:
                raise ServiceError("order_not_owned", "只有租约持有人可以退回处置单", 409)
            db.execute("UPDATE treatment_orders SET status='open', assignee_id=NULL, lease_owner=NULL, lease_until='', updated_at=? WHERE id=?", (at, order_id))
            self._set_artifact_status(db, project_id, order["artifact_id"], "stored", actor["id"], f"处置单 {order_id} 退回", at)
            self.research.audit("order.return", "treatment_order", str(order_id), {"reason": reason}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, order_id, at)

    def cancel_order(self, project_id: int, actor: Any, order_id: int, at: str | None = None) -> dict[str, Any]:
        self.research.require_role(project_id, actor["id"], LEAD_ROLES)
        at = at or now()
        with transaction(immediate=True) as db:
            order = self._get_order(db, project_id, order_id)
            if order["status"] not in ("open", "leased"):
                raise ServiceError("order_closed", "处置单已关闭", 409)
            db.execute("UPDATE treatment_orders SET status='cancelled', lease_owner=NULL, lease_until='', updated_at=? WHERE id=?", (at, order_id))
            self.research.audit("order.cancel", "treatment_order", str(order_id), {}, project_id=project_id, actor_id=actor["id"])
            return self._order_public(db, project_id, order_id, at)

    # ---- 租约恢复（进程重启后调用，也在领取/转交/完成/退回时惰性执行） ----
    def recover_expired_leases(self, project_id: int | None = None, at: str | None = None) -> int:
        at = at or now()
        with transaction(immediate=True) as db:
            return self._recover_project_leases(db, project_id, at)

    def _recover_project_leases(self, db: sqlite3.Connection, project_id: int | None, at: str) -> int:
        sql = "SELECT * FROM treatment_orders WHERE status='leased' AND lease_until< ?"
        params: list[Any] = [at]
        if project_id is not None:
            sql += " AND project_id=?"
            params.append(project_id)
        rows = db.execute(sql, params).fetchall()
        for row in rows:
            db.execute("UPDATE treatment_orders SET status='open', lease_owner=NULL, lease_until='', updated_at=? WHERE id=?", (at, row["id"]))
            self.research.audit("order.lease_expired", "treatment_order", str(row["id"]), {"lease_owner": row["lease_owner"], "lease_until": row["lease_until"]}, project_id=row["project_id"], actor_id=None)
        return len(rows)
