"""有机遗物保护处置领域服务。

所有跨表写入都在单个即时事务中完成；鉴权、审计、库位脱敏、告警去重与
升级、租约恢复均集中在本层。时间一律走 ``app.organics.clock`` 的 UTC 工具。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app.database import connection, now as base_now, transaction
from app.organics.clock import add_minutes, format_ts, now, now_dt, parse_ts
from app.organics.engine import Rule, Window, classify, level_for, missing_gaps
from app.security import request_hash, sanitize, stable_json

# 可看到敏感库位的角色；其余角色在所有接口里拿到脱敏后的 location_code
LOCATION_VISIBLE_ROLES = {"owner", "conservator", "recorder"}
# 只有指定保护人员（含项目 owner）可以领取/转交/完成/退回处置单
HANDLING_ROLES = {"owner", "conservator"}
REGISTRY_ROLES = {"owner", "conservator", "recorder"}
THRESHOLD_ROLES = {"owner", "conservator"}

LEASE_MINUTES = 30
MISSING_KIND = "missing"
LEVEL_RANK = {"warning": 1, "serious": 2, "critical": 3}


class ServiceError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


class OrganicService:
    def __init__(self, db: sqlite3.Connection | None = None):
        self.db = db or connection()

    # ------------------------------------------------------------------ 通用

    def audit(self, action: str, project_id: int, actor_id: int, resource_type: str, resource_id: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO audit_events(project_id,actor_id,action,resource_type,resource_id,payload_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (project_id, actor_id, action, resource_type, resource_id, stable_json(sanitize(payload)), base_now()),
        )

    def role(self, project_id: int, user_id: int) -> str:
        row = self.db.execute(
            "SELECT role FROM project_members WHERE project_id=? AND user_id=?", (project_id, user_id)
        ).fetchone()
        if row is None:
            raise ServiceError("forbidden", "当前用户不属于该项目", 403)
        return row["role"]

    def require_any_member(self, project_id: int, user_id: int) -> str:
        return self.role(project_id, user_id)

    def require_role(self, project_id: int, user_id: int, allowed: set[str]) -> str:
        value = self.role(project_id, user_id)
        if value not in allowed:
            raise ServiceError("forbidden", "当前角色无权执行该操作", 403)
        return value

    def mask_location(self, data: dict[str, Any], role: str) -> dict[str, Any]:
        if role not in LOCATION_VISIBLE_ROLES and data.get("location_code"):
            data["location_code"] = "***"
        return data

    def _artifact(self, project_id: int, temp_number: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM org_artifacts WHERE project_id=? AND temp_number=?", (project_id, temp_number)
        ).fetchone()
        if row is None:
            raise ServiceError("artifact_not_found", f"未找到临时编号 {temp_number} 的遗物", 404)
        return row

    def _artifact_by_id(self, project_id: int, artifact_id: int) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM org_artifacts WHERE project_id=? AND id=?", (project_id, artifact_id)
        ).fetchone()
        if row is None:
            raise ServiceError("artifact_not_found", "遗物不存在", 404)
        return row

    def _active_scheme(self, project_id: int, material_kind: str) -> tuple[int, dict[str, Rule]]:
        row = self.db.execute(
            "SELECT * FROM org_threshold_schemes WHERE project_id=? AND material_kind=? AND active=1 ORDER BY version DESC LIMIT 1",
            (project_id, material_kind),
        ).fetchone()
        if row is None:
            return 0, {}
        rules = {item["metric"]: Rule.from_dict(item) for item in json.loads(row["rules_json"])}
        return row["version"], rules

    def _windows(self, project_id: int) -> list[Window]:
        rows = self.db.execute(
            "SELECT * FROM org_maintenance_windows WHERE project_id=? ORDER BY start_at", (project_id,)
        ).fetchall()
        return [Window.from_row(row) for row in rows]

    def _chain(
        self,
        project_id: int,
        artifact_id: int,
        event_type: str,
        actor_id: int,
        *,
        from_package_id: int | None = None,
        to_package_id: int | None = None,
        location_code: str = "",
        ref_type: str = "",
        ref_id: str = "",
        detail: dict[str, Any] | None = None,
        stamp: str | None = None,
    ) -> None:
        self.db.execute(
            "INSERT INTO org_artifact_chain(project_id,artifact_id,event_type,from_package_id,to_package_id,"
            "location_code,ref_type,ref_id,actor_id,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                project_id,
                artifact_id,
                event_type,
                from_package_id,
                to_package_id,
                location_code,
                ref_type,
                ref_id,
                actor_id,
                stable_json(detail or {}),
                stamp or now(),
            ),
        )

    # ------------------------------------------------------------------ 遗物

    def register_artifact(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        stamp = now()
        try:
            with transaction(immediate=True) as db:
                cursor = db.execute(
                    "INSERT INTO org_artifacts(project_id,temp_number,material_kind,material_detail,burial_env,"
                    "storage_state,container_code,immersion_fluid,location_code,notes,created_by,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        project_id,
                        payload["temp_number"],
                        payload["material_kind"],
                        payload.get("material_detail", ""),
                        payload["burial_env"],
                        payload["storage_state"],
                        payload.get("container_code", ""),
                        payload.get("immersion_fluid", ""),
                        payload.get("location_code", ""),
                        payload.get("notes", ""),
                        user["id"],
                        stamp,
                        stamp,
                    ),
                )
                artifact_id = cursor.lastrowid
                self._chain(project_id, artifact_id, "register", user["id"], location_code=payload.get("location_code", ""), detail=payload, stamp=stamp)
                self.audit("artifact.register", project_id, user["id"], "artifact", str(artifact_id), payload)
                row = db.execute("SELECT * FROM org_artifacts WHERE id=?", (artifact_id,)).fetchone()
                return self.mask_location(dict(row), self.role(project_id, user["id"]))
        except sqlite3.IntegrityError as exc:
            raise ServiceError("artifact_exists", "该项目下临时编号已存在", 409) from exc

    def update_artifact(self, project_id: int, temp_number: str, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        role = self.require_role(project_id, user["id"], REGISTRY_ROLES)
        current = self._artifact(project_id, temp_number)
        fields = {key: value for key, value in payload.items() if value is not None}
        if not fields:
            return self.mask_location(dict(current), role)
        stamp = now()
        with transaction(immediate=True) as db:
            assignments = ", ".join(f"{key}=?" for key in fields)
            db.execute(
                f"UPDATE org_artifacts SET {assignments}, updated_at=? WHERE id=?",
                (*fields.values(), stamp, current["id"]),
            )
            if "location_code" in fields or "container_code" in fields or "storage_state" in fields:
                self._chain(
                    project_id,
                    current["id"],
                    "location",
                    user["id"],
                    location_code=fields.get("location_code", current["location_code"]),
                    detail={"before": {key: current[key] for key in fields}, "after": fields},
                    stamp=stamp,
                )
            self.audit("artifact.update", project_id, user["id"], "artifact", str(current["id"]), {"temp_number": temp_number, **fields})
            row = db.execute("SELECT * FROM org_artifacts WHERE id=?", (current["id"],)).fetchone()
            return self.mask_location(dict(row), role)

    def list_artifacts(self, project_id: int, user: sqlite3.Row, material_kind: str | None = None) -> dict[str, Any]:
        role = self.require_any_member(project_id, user["id"])
        if material_kind:
            rows = self.db.execute(
                "SELECT * FROM org_artifacts WHERE project_id=? AND material_kind=? ORDER BY id",
                (project_id, material_kind),
            ).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM org_artifacts WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
        return {"data": [self.mask_location(dict(row), role) for row in rows]}

    def get_artifact(self, project_id: int, temp_number: str, user: sqlite3.Row) -> dict[str, Any]:
        role = self.require_any_member(project_id, user["id"])
        return self.mask_location(dict(self._artifact(project_id, temp_number)), role)

    def artifact_chain(self, project_id: int, temp_number: str, user: sqlite3.Row) -> dict[str, Any]:
        role = self.require_any_member(project_id, user["id"])
        artifact = self._artifact(project_id, temp_number)
        rows = self.db.execute(
            "SELECT c.*, p.package_code AS from_package_code, q.package_code AS to_package_code "
            "FROM org_artifact_chain c "
            "LEFT JOIN org_packages p ON p.id=c.from_package_id "
            "LEFT JOIN org_packages q ON q.id=c.to_package_id "
            "WHERE c.artifact_id=? ORDER BY c.id",
            (artifact["id"],),
        ).fetchall()
        data = []
        for row in rows:
            item = dict(row)
            if role not in LOCATION_VISIBLE_ROLES and item.get("location_code"):
                item["location_code"] = "***"
            data.append(item)
        return {"temp_number": temp_number, "data": data}

    # ------------------------------------------------------------------ 阈值

    def publish_scheme(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], THRESHOLD_ROLES)
        material_kind = payload["material_kind"]
        rules = payload["rules"]
        stamp = now()
        with transaction(immediate=True) as db:
            row = db.execute(
                "SELECT COALESCE(MAX(version),0) AS v FROM org_threshold_schemes WHERE project_id=? AND material_kind=?",
                (project_id, material_kind),
            ).fetchone()
            version = row["v"] + 1
            db.execute("UPDATE org_threshold_schemes SET active=0 WHERE project_id=? AND material_kind=? AND active=1", (project_id, material_kind))
            cursor = db.execute(
                "INSERT INTO org_threshold_schemes(project_id,material_kind,version,active,rules_json,created_by,created_at) "
                "VALUES(?,?,?,1,?,?,?)",
                (project_id, material_kind, version, stable_json(rules), user["id"], stamp),
            )
            self.audit("threshold.scheme_publish", project_id, user["id"], "threshold_scheme", str(cursor.lastrowid),
                       {"material_kind": material_kind, "version": version, "rules": rules})
            return {"id": cursor.lastrowid, "material_kind": material_kind, "version": version, "active": 1,
                    "rules": rules, "created_at": stamp}

    def list_schemes(self, project_id: int, material_kind: str | None, user: sqlite3.Row) -> dict[str, Any]:
        self.require_any_member(project_id, user["id"])
        if material_kind:
            rows = self.db.execute(
                "SELECT * FROM org_threshold_schemes WHERE project_id=? AND material_kind=? ORDER BY material_kind,version",
                (project_id, material_kind),
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM org_threshold_schemes WHERE project_id=? ORDER BY material_kind,version", (project_id,)
            ).fetchall()
        return {"data": [
            {"id": row["id"], "material_kind": row["material_kind"], "version": row["version"], "active": bool(row["active"]),
             "rules": json.loads(row["rules_json"]), "created_at": row["created_at"]}
            for row in rows
        ]}

    # -------------------------------------------------------------- 维护窗口

    def create_maintenance_window(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        start = parse_ts(payload["start_at"])
        end = parse_ts(payload["end_at"])
        if end <= start:
            raise ServiceError("invalid_window", "维护窗口结束时间必须晚于开始时间", 422)
            raise ServiceError("invalid_window", "维护窗口结束时间必须晚于开始时间", 422)
        stamp = now()
        with transaction(immediate=True) as db:
            cursor = db.execute(
                "INSERT INTO org_maintenance_windows(project_id,location_code,metric,start_at,end_at,reason,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (project_id, payload.get("location_code", ""), payload.get("metric", ""), format_ts(start), format_ts(end),
                 payload.get("reason", ""), user["id"], stamp),
            )
            self.audit("maintenance.window_create", project_id, user["id"], "maintenance_window", str(cursor.lastrowid), payload)
            return {"id": cursor.lastrowid, "start_at": format_ts(start), "end_at": format_ts(end),
                    "location_code": payload.get("location_code", ""), "metric": payload.get("metric", ""),
                    "reason": payload.get("reason", "")}

    # ------------------------------------------------------------ 传感批次

    def import_batch(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        batch_ref = payload["batch_ref"]
        digest = request_hash(payload)

        existing = self.db.execute(
            "SELECT * FROM org_sensor_batches WHERE project_id=? AND batch_ref=?", (project_id, batch_ref)
        ).fetchone()
        if existing is not None:
            # 重复批次：同内容确定性重放既定结果；不同内容拒绝，防止引用方误用
            if existing["payload_hash"] != digest:
                raise ServiceError("batch_conflict", "同名批次的内容与首次导入不一致", 409)
            return {**json.loads(existing["summary_json"]), "replayed": True}

        # 入库前先做全部校验，任何一条失败都不开事务，整体即"失败事务"
        normalized: list[dict[str, Any]] = []
        for raw in payload["readings"]:
            try:
                measured = parse_ts(raw["measured_at"])
            except (ValueError, TypeError) as exc:
                raise ServiceError("invalid_timestamp", f"无法解析时间戳：{raw['measured_at']}", 422) from exc
            artifact_id: int | None = None
            location_code = raw.get("location_code", "")
            temp_number = raw.get("artifact_temp_number")
            if temp_number:
                artifact = self._artifact(project_id, temp_number)
                artifact_id = artifact["id"]
                if not location_code:
                    location_code = artifact["location_code"]
            elif not location_code:
                raise ServiceError("reading_unbound", "每条读数必须给出遗物临时编号或库位", 422)
            normalized.append(
                {"artifact_id": artifact_id, "location_code": location_code, "metric": raw["metric"],
                 "value": float(raw["value"]), "measured_at": format_ts(measured)}
            )

        stamp = now()
        with transaction(immediate=True) as db:
            cursor = db.execute(
                "INSERT INTO org_sensor_batches(project_id,batch_ref,source,payload_hash,imported_by,received_at,reading_count) "
                "VALUES(?,?,?,?,?,?,0)",
                (project_id, batch_ref, payload.get("source", ""), digest, user["id"], stamp),
            )
            batch_id = cursor.lastrowid
            new_count = 0
            duplicate_count = 0
            for item in normalized:
                try:
                    db.execute(
                        "INSERT INTO org_sensor_readings(project_id,batch_id,artifact_id,location_code,metric,value,measured_at,ingested_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (project_id, batch_id, item["artifact_id"], item["location_code"], item["metric"],
                         item["value"], item["measured_at"], stamp),
                    )
                    new_count += 1
                except sqlite3.IntegrityError:
                    duplicate_count += 1

            windows = [Window.from_row(row) for row in db.execute(
                "SELECT * FROM org_maintenance_windows WHERE project_id=? ORDER BY start_at", (project_id,)
            ).fetchall()]

            alerts_out: list[dict[str, Any]] = []
            todos_out: list[dict[str, Any]] = []
            affected_pairs = {(item["artifact_id"], item["metric"]) for item in normalized if item["artifact_id"] is not None}
            for artifact_id, metric in sorted(affected_pairs):
                artifact = self._artifact_by_id(project_id, artifact_id)
                version, rules = self._active_scheme(project_id, artifact["material_kind"])
                rule = rules.get(metric)
                if rule is None:
                    continue
                alerts_out, todos_out = self._evaluate_metric(
                    db, project_id, artifact, metric, rule, version, windows, alerts_out, todos_out, user["id"]
                )

            summary = {
                "batch_id": batch_id,
                "batch_ref": batch_ref,
                "readings_received": len(normalized),
                "readings_imported": new_count,
                "duplicates": duplicate_count,
                "alerts": alerts_out,
                "todos": todos_out,
            }
            db.execute("UPDATE org_sensor_batches SET reading_count=?, summary_json=? WHERE id=?",
                       (new_count, stable_json(summary), batch_id))
            self.audit("sensor.batch_import", project_id, user["id"], "sensor_batch", str(batch_id),
                       {"batch_ref": batch_ref, "readings_received": len(normalized),
                        "readings_imported": new_count, "duplicates": duplicate_count,
                        "alert_ids": [item["id"] for item in alerts_out],
                        "todo_ids": [item["id"] for item in todos_out]})
            return {**summary, "replayed": False}

    def _evaluate_metric(
        self,
        db: sqlite3.Connection,
        project_id: int,
        artifact: sqlite3.Row,
        metric: str,
        rule: Rule,
        scheme_version: int,
        windows: list[Window],
        alerts_out: list[dict[str, Any]],
        todos_out: list[dict[str, Any]],
        actor_id: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """对单件遗物的单个指标，用全部历史读数重算越界段并与既有告警对齐。"""
        rows = db.execute(
            "SELECT * FROM org_sensor_readings WHERE project_id=? AND artifact_id=? AND metric=? ORDER BY measured_at,id",
            (project_id, artifact["id"], metric),
        ).fetchall()
        readings = [
            {"id": row["id"], "at": parse_ts(row["measured_at"]), "value": row["value"],
             "location": row["location_code"]}
            for row in rows
        ]

        # 连续越界段：同一方向（low/high）的相邻越界读数，被正常读数打断即分段
        runs: list[dict[str, Any]] = []
        run_keys: list[str] = []
        current: dict[str, Any] | None = None
        for index, reading in enumerate(readings):
            kind = classify(reading["value"], rule)
            if kind is None:
                if current is not None:
                    current["resolved_at"] = reading["at"]
                    current = None
                continue
            if current is None or current["kind"] != kind:
                if current is not None:
                    runs.append(current)
                current = {"kind": kind, "items": [reading], "resolved_at": None}
            else:
                current["items"].append(reading)
        if current is not None:
            runs.append(current)

        for run in runs:
            items = run["items"]
            first_item, last_item = items[0], items[-1]
            duration = (last_item["at"] - first_item["at"]).total_seconds() / 60.0
            level = level_for(duration, rule)
            escalations: list[dict[str, Any]] = []
            seen_level = "warning"
            for item in items:
                item_level = level_for((item["at"] - first_item["at"]).total_seconds() / 60.0, rule)
                if item_level != seen_level:
                    escalations.append({"at": format_ts(item["at"]), "level": item_level, "reading_id": item["id"]})
                    seen_level = item_level
            is_open = run["resolved_at"] is None and last_item["at"] == readings[-1]["at"]
            status = "resolved"
            if is_open:
                status = "escalated" if level in {"serious", "critical"} else "open"
            dedup_key = f"{artifact['id']}:{metric}:{run['kind']}:{first_item['id']}"
            run_keys.append(dedup_key)
            alert = self._upsert_alert(
                db, project_id, artifact["id"], metric, run["kind"], dedup_key, level, status,
                scheme_version, first_item["at"], last_item["at"], run["resolved_at"],
                escalations, [item["id"] for item in items],
            )
            alerts_out.append(alert)
            if level in {"serious", "critical"}:
                todos_out.append(self._ensure_todo(db, project_id, alert, artifact, actor_id))

        # 乱序补点可能把旧越界段并入新段：本次重算后不再成立的开放告警一律收敛，
        # 保证同一指标同一方向在任意时刻至多一条开放告警。
        resolve_stamp = format_ts(readings[-1]["at"]) if readings else now()
        if run_keys:
            marks = ",".join("?" for _ in run_keys)
            stale = db.execute(
                f"SELECT id FROM org_alerts WHERE project_id=? AND artifact_id=? AND metric=? "
                f"AND violation_kind!='{MISSING_KIND}' AND status!='resolved' AND dedup_key NOT IN ({marks})",
                (project_id, artifact["id"], metric, *sorted(run_keys)),
            ).fetchall()
        else:
            stale = db.execute(
                "SELECT id FROM org_alerts WHERE project_id=? AND artifact_id=? AND metric=? "
                "AND violation_kind!=? AND status!='resolved'",
                (project_id, artifact["id"], metric, MISSING_KIND),
            ).fetchall()
        for item in stale:
            db.execute("UPDATE org_alerts SET status='resolved',resolved_at=? WHERE id=?", (resolve_stamp, item["id"]))
            self.audit("alert.resolve", project_id, None, "alert", str(item["id"]),
                       {"artifact_id": artifact["id"], "metric": metric, "reason": "superseded_by_recomputation"})

        # 缺测：相邻读数间隔超阈值，且缺口未被维护窗口完全覆盖
        location = artifact["location_code"]
        gaps = missing_gaps([item["at"] for item in readings], rule, windows, location)
        for gap_start, gap_end in gaps:
            prev_item = next(item for item in readings if item["at"] == gap_start)
            next_item = next(item for item in readings if item["at"] == gap_end)
            gap_minutes = (gap_end - gap_start).total_seconds() / 60.0
            level = level_for(gap_minutes, rule)
            dedup_key = f"{artifact['id']}:{metric}:{MISSING_KIND}:{prev_item['id']}:{next_item['id']}"
            alert = self._upsert_alert(
                db, project_id, artifact["id"], metric, MISSING_KIND, dedup_key, level, "resolved",
                scheme_version, gap_start, gap_end, gap_end, [], [prev_item["id"], next_item["id"]],
            )
            alerts_out.append(alert)
            if level in {"serious", "critical"}:
                todos_out.append(self._ensure_todo(db, project_id, alert, artifact, actor_id))

        alerts_out.sort(key=lambda item: item["id"])
        todos_out.sort(key=lambda item: item["id"])
        return alerts_out, todos_out

    def _upsert_alert(
        self, db: sqlite3.Connection, project_id: int, artifact_id: int, metric: str, violation_kind: str,
        dedup_key: str, level: str, status: str, scheme_version: int,
        first_at: datetime, latest_at: datetime, resolved_at: datetime | None,
        escalations: list[dict[str, Any]], reading_ids: list[int],
    ) -> dict[str, Any]:
        existing = db.execute(
            "SELECT * FROM org_alerts WHERE project_id=? AND dedup_key=?", (project_id, dedup_key)
        ).fetchone()
        resolved_text = format_ts(resolved_at) if resolved_at else ""
        if existing is not None:
            # 去重：同一越界段只维护一条告警，重复/乱序回放产生同样结果
            db.execute(
                "UPDATE org_alerts SET level=?, status=?, latest_reading_at=?, resolved_at=?, "
                "escalations_json=?, reading_ids_json=? WHERE id=?",
                (level, status, format_ts(latest_at), resolved_text,
                 stable_json(escalations), stable_json(reading_ids), existing["id"]),
            )
            alert_id = existing["id"]
            # 任何状态转换都留审计：升级、解决分别记录，且只在真正变化时记录
            if existing["status"] != "resolved" and status == "resolved":
                self.audit("alert.resolve", project_id, None, "alert", str(alert_id),
                           {"artifact_id": artifact_id, "metric": metric, "violation_kind": violation_kind,
                            "from_status": existing["status"], "level": level})
            elif LEVEL_RANK[level] > LEVEL_RANK[existing["level"]] or (
                existing["status"] == "open" and status == "escalated"
            ):
                self.audit("alert.escalate", project_id, None, "alert", str(alert_id),
                           {"artifact_id": artifact_id, "metric": metric, "violation_kind": violation_kind,
                            "from_level": existing["level"], "to_level": level, "status": status})
        else:
            cursor = db.execute(
                "INSERT INTO org_alerts(project_id,artifact_id,metric,violation_kind,dedup_key,level,status,"
                "scheme_version,first_reading_at,latest_reading_at,resolved_at,escalations_json,reading_ids_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (project_id, artifact_id, metric, violation_kind, dedup_key, level, status, scheme_version,
                 format_ts(first_at), format_ts(latest_at), resolved_text,
                 stable_json(escalations), stable_json(reading_ids)),
            )
            alert_id = cursor.lastrowid
            self.audit("alert.raise", project_id, None, "alert", str(alert_id),
                       {"artifact_id": artifact_id, "metric": metric, "violation_kind": violation_kind,
                        "level": level, "dedup_key": dedup_key})
        return {"id": alert_id, "artifact_id": artifact_id, "metric": metric, "violation_kind": violation_kind,
                "level": level, "status": status, "first_reading_at": format_ts(first_at),
                "latest_reading_at": format_ts(latest_at), "resolved_at": resolved_text}

    def _ensure_todo(
        self, db: sqlite3.Connection, project_id: int, alert: dict[str, Any], artifact: sqlite3.Row, actor_id: int
    ) -> dict[str, Any]:
        """严重及以上告警对应一张待处置单；同一条告警重复评估不重复开单。"""
        existing = db.execute(
            "SELECT * FROM org_handling_orders WHERE project_id=? AND alert_id=? AND status IN ('queued','claimed')",
            (project_id, alert["id"]),
        ).fetchone()
        priority = "urgent" if alert["level"] == "critical" else "high"
        existing = db.execute(
            "SELECT * FROM org_handling_orders WHERE project_id=? AND alert_id=? ORDER BY id LIMIT 1",
            (project_id, alert["id"]),
        ).fetchone()
        if existing is not None:
            if existing["status"] in {"queued", "claimed"} and existing["priority"] != priority:
                db.execute("UPDATE org_handling_orders SET priority=? WHERE id=?", (priority, existing["id"]))
            return {"id": existing["id"], "order_no": existing["order_no"], "priority": existing["priority"], "status": existing["status"]}
        stamp = now()
        order_no = f"A{alert['id']:06d}"
        cursor = db.execute(
            "INSERT INTO org_handling_orders(project_id,order_no,kind,priority,reason,artifact_ids_json,alert_id,"
            "status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'queued',?,?,?)",
            (project_id, order_no, "inspection", priority,
             f"告警 #{alert['id']} {alert['metric']} {alert['violation_kind']} 达到 {alert['level']}",
             stable_json([artifact["id"]]), alert["id"], actor_id, stamp, stamp),
        )
        order_id = cursor.lastrowid
        db.execute("UPDATE org_alerts SET todo_order_id=? WHERE id=?", (order_id, alert["id"]))
        self._chain(project_id, artifact["id"], "note", actor_id, ref_type="handling_order", ref_id=str(order_id),
                    detail={"alert_id": alert["id"], "auto_todo": True}, stamp=stamp)
        self.audit("order.auto_create", project_id, actor_id, "handling_order", str(order_id),
                   {"alert_id": alert["id"], "order_no": order_no, "priority": priority})
        return {"id": order_id, "order_no": order_no, "priority": priority, "status": "queued"}

    def list_alerts(self, project_id: int, user: sqlite3.Row, status_filter: str | None = None) -> dict[str, Any]:
        role = self.require_any_member(project_id, user["id"])
        sql = (
            "SELECT a.*, ar.temp_number, ar.location_code AS artifact_location, ar.material_kind "
            "FROM org_alerts a JOIN org_artifacts ar ON ar.id=a.artifact_id WHERE a.project_id=?"
        )
        params: list[Any] = [project_id]
        if status_filter:
            sql += " AND a.status=?"
            params.append(status_filter)
        sql += " ORDER BY a.id"
        rows = self.db.execute(sql, params).fetchall()
        data = []
        for row in rows:
            item = {key: row[key] for key in row.keys() if key != "artifact_location"}
            item["location_code"] = row["artifact_location"] or ""
            if role not in LOCATION_VISIBLE_ROLES and item["location_code"]:
                item["location_code"] = "***"
            data.append(item)
        return {"data": data}

    # ------------------------------------------------------------------ 包装

    def _package(self, project_id: int, code: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM org_packages WHERE project_id=? AND package_code=?", (project_id, code)
        ).fetchone()
        if row is None:
            raise ServiceError("package_not_found", f"包装 {code} 不存在", 404)
        return row

    def _active_package_artifacts(self, db: sqlite3.Connection, package_id: int) -> list[sqlite3.Row]:
        return db.execute(
            "SELECT a.* FROM org_package_items i JOIN org_artifacts a ON a.id=i.artifact_id "
            "WHERE i.package_id=? AND i.removed_at='' ORDER BY a.id",
            (package_id,),
        ).fetchall()

    def _create_package_row(self, db: sqlite3.Connection, project_id: int, code: str, stamp: str, parent_id: int | None = None) -> int:
        try:
            cursor = db.execute(
                "INSERT INTO org_packages(project_id,package_code,status,parent_package_id,created_at,updated_at) "
                "VALUES(?,?,'active',?,?,?)",
                (project_id, code, parent_id, stamp, stamp),
            )
        except sqlite3.IntegrityError as exc:
            raise ServiceError("package_exists", f"包装编号 {code} 已存在", 409) from exc
        return cursor.lastrowid

    def create_package(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        stamp = now()
        with transaction(immediate=True) as db:
            package_id = self._create_package_row(db, project_id, payload["package_code"], stamp)
            artifacts = [self._artifact(project_id, number) for number in payload.get("artifact_temp_numbers", [])]
            change_cursor = db.execute(
                "INSERT INTO org_package_changes(project_id,change_type,target_package_id,artifact_ids_json,actor_id,note,created_at) "
                "VALUES(?,'create',?,?,?,?,?)",
                (project_id, package_id, stable_json([row["id"] for row in artifacts]), user["id"], "", stamp),
            )
            for artifact in artifacts:
                db.execute(
                    "INSERT INTO org_package_items(package_id,artifact_id,added_at,change_id) VALUES(?,?,?,?)",
                    (package_id, artifact["id"], stamp, change_cursor.lastrowid),
                )
                self._chain(project_id, artifact["id"], "repackage", user["id"], to_package_id=package_id,
                            ref_type="package_change", ref_id=str(change_cursor.lastrowid), stamp=stamp)
            self.audit("package.create", project_id, user["id"], "package", str(package_id),
                       {"package_code": payload["package_code"], "artifacts": [row["temp_number"] for row in artifacts]})
            return self._package_view(db, project_id, package_id, self.role(project_id, user["id"]))

    def merge_packages(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        codes = payload["source_package_codes"]
        if len(set(codes)) != len(codes):
            raise ServiceError("invalid_merge", "来源包装重复", 422)
        stamp = now()
        with transaction(immediate=True) as db:
            sources = [self._package(project_id, code) for code in codes]
            for source in sources:
                if source["status"] != "active":
                    raise ServiceError("package_not_active", f"包装 {source['package_code']} 不是可用状态", 409)
            if payload["target_package_code"] in codes:
                raise ServiceError("invalid_merge", "目标包装不能与来源包装相同", 422)
            target_id = self._create_package_row(db, project_id, payload["target_package_code"], stamp)
            moved: list[sqlite3.Row] = []
            for source in sources:
                items = self._active_package_artifacts(db, source["id"])
                moved.extend(items)
                for artifact in items:
                    db.execute("UPDATE org_package_items SET removed_at=? WHERE package_id=? AND artifact_id=? AND removed_at=''",
                               (stamp, source["id"], artifact["id"]))
                    db.execute(
                        "INSERT INTO org_package_items(package_id,artifact_id,added_at) VALUES(?,?,?)",
                        (target_id, artifact["id"], stamp),
                    )
                    self._chain(project_id, artifact["id"], "merge", user["id"],
                                from_package_id=source["id"], to_package_id=target_id,
                                location_code=artifact["location_code"], stamp=stamp)
                db.execute("UPDATE org_packages SET status='merged',parent_package_id=?,updated_at=? WHERE id=?",
                           (target_id, stamp, source["id"]))
            change = db.execute(
                "INSERT INTO org_package_changes(project_id,change_type,source_package_ids_json,target_package_id,"
                "artifact_ids_json,actor_id,note,created_at) VALUES(?,'merge',?,?,?,?,?,?)",
                (project_id, stable_json([row["id"] for row in sources]), target_id,
                 stable_json([row["id"] for row in moved]), user["id"], "", stamp),
            )
            self.audit("package.merge", project_id, user["id"], "package_change", str(change.lastrowid),
                       {"sources": codes, "target": payload["target_package_code"],
                        "artifacts": [row["temp_number"] for row in moved]})
            return self._package_view(db, project_id, target_id, self.role(project_id, user["id"]))

    def split_packages(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        stamp = now()
        with transaction(immediate=True) as db:
            source = self._package(project_id, payload["source_package_code"])
            if source["status"] != "active":
                raise ServiceError("package_not_active", "来源包装不是可用状态", 409)
            targets = payload["target_package_codes"]
            groups = payload["groups"]
            if len(targets) != len(groups) or len(set(targets)) != len(targets):
                raise ServiceError("invalid_split", "目标包装与分组数量必须一致且不重复", 422)
            current = self._active_package_artifacts(db, source["id"])
            current_ids = {row["id"]: row for row in current}
            grouped: dict[int, list[sqlite3.Row]] = {}
            seen: set[int] = set()
            for code, numbers in zip(targets, groups):
                artifacts = [self._artifact(project_id, number) for number in numbers]
                for artifact in artifacts:
                    if artifact["id"] not in current_ids:
                        raise ServiceError("artifact_not_in_package", f"{artifact['temp_number']} 不在来源包装中", 409)
                    if artifact["id"] in seen:
                        raise ServiceError("invalid_split", "同一件遗物不能同时进入多个目标包装", 409)
                    seen.add(artifact["id"])
                grouped[code] = artifacts
            if seen != set(current_ids):
                raise ServiceError("invalid_split", "拆分分组必须覆盖来源包装内的全部遗物，不能遗漏", 409)
            target_ids: list[int] = []
            for code in targets:
                target_ids.append(self._create_package_row(db, project_id, code, stamp, parent_id=source["id"]))
            for code, target_id, artifacts in zip(targets, target_ids, [grouped[item] for item in targets]):
                for artifact in artifacts:
                    db.execute("UPDATE org_package_items SET removed_at=? WHERE package_id=? AND artifact_id=? AND removed_at=''",
                               (stamp, source["id"], artifact["id"]))
                    db.execute(
                        "INSERT INTO org_package_items(package_id,artifact_id,added_at) VALUES(?,?,?)",
                        (target_id, artifact["id"], stamp),
                    )
                    self._chain(project_id, artifact["id"], "split", user["id"],
                                from_package_id=source["id"], to_package_id=target_id,
                                location_code=artifact["location_code"],
                                detail={"target_code": code}, stamp=stamp)
            db.execute("UPDATE org_packages SET status='split',updated_at=? WHERE id=?", (stamp, source["id"]))
            change = db.execute(
                "INSERT INTO org_package_changes(project_id,change_type,source_package_ids_json,target_package_id,"
                "artifact_ids_json,actor_id,note,created_at) VALUES(?,'split',?,?,?,?,?,?)",
                (project_id, stable_json([source["id"]]), None,
                 stable_json([artifact["id"] for artifacts in grouped.values() for artifact in artifacts]),
                 user["id"], stable_json({"targets": dict(zip(targets, [[a["temp_number"] for a in grouped[c]] for c in targets]))}), stamp),
            )
            self.audit("package.split", project_id, user["id"], "package_change", str(change.lastrowid),
                       {"source": payload["source_package_code"], "targets": targets})
            return {"source_package_code": source["package_code"], "targets": [
                self._package_view(db, project_id, target_id, self.role(project_id, user["id"])) for target_id in target_ids
            ]}

    def _package_view(self, db: sqlite3.Connection, project_id: int, package_id: int, role: str) -> dict[str, Any]:
        package = db.execute("SELECT * FROM org_packages WHERE id=?", (package_id,)).fetchone()
        items = db.execute(
            "SELECT a.id,a.temp_number,a.material_kind,a.location_code,a.container_code,i.added_at,i.removed_at "
            "FROM org_package_items i JOIN org_artifacts a ON a.id=i.artifact_id WHERE i.package_id=? ORDER BY a.id",
            (package_id,),
        ).fetchall()
        data = []
        for row in items:
            item = dict(row)
            if role not in LOCATION_VISIBLE_ROLES and item.get("location_code"):
                item["location_code"] = "***"
            data.append(item)
        result = dict(package)
        result["items"] = data
        return result

    def get_package(self, project_id: int, code: str, user: sqlite3.Row) -> dict[str, Any]:
        role = self.require_any_member(project_id, user["id"])
        package = self._package(project_id, code)
        return self._package_view(self.db, project_id, package["id"], role)

    # ------------------------------------------------------------------ 处置单

    def create_order(self, project_id: int, payload: dict[str, Any], user: sqlite3.Row) -> dict[str, Any]:
        self.require_role(project_id, user["id"], REGISTRY_ROLES)
        artifact_ids: list[int] = []
        for number in payload.get("artifact_temp_numbers", []):
            artifact_ids.append(self._artifact(project_id, number)["id"])
        package_id = None
        if payload.get("package_code"):
            package = self._package(project_id, payload["package_code"])
            package_id = package["id"]
            # 按包装开单时，把包装内全部在籍遗物纳入单据，逐件保留链路
            if not artifact_ids:
                artifact_ids = [row["id"] for row in self._active_package_artifacts(self.db, package_id)]
        stamp = now()
        try:
            with transaction(immediate=True) as db:
                cursor = db.execute(
                    "INSERT INTO org_handling_orders(project_id,order_no,kind,priority,reason,artifact_ids_json,"
                    "package_id,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'queued',?,?,?)",
                    (project_id, payload["order_no"], payload["kind"], payload["priority"], payload.get("reason", ""),
                     stable_json(artifact_ids), package_id, user["id"], stamp, stamp),
                )
                order_id = cursor.lastrowid
                for artifact_id in artifact_ids:
                    self._chain(project_id, artifact_id, "note", user["id"], ref_type="handling_order", ref_id=str(order_id),
                                detail={"order_no": payload["order_no"], "kind": payload["kind"]}, stamp=stamp)
                self.audit("order.create", project_id, user["id"], "handling_order", str(order_id),
                           {"order_no": payload["order_no"], "kind": payload["kind"], "artifacts": artifact_ids})
                return self._order_view(db, db.execute("SELECT * FROM org_handling_orders WHERE id=?", (order_id,)).fetchone())
        except sqlite3.IntegrityError as exc:
            raise ServiceError("order_exists", "处置单编号已存在", 409) from exc

    def _recover_expired(self, db: sqlite3.Connection, project_id: int) -> None:
        """把到期未完成的租约放回队列。状态全部持久化，进程重启后依旧生效。"""
        stamp_text = now()
        rows = db.execute(
            "SELECT * FROM org_handling_orders WHERE project_id=? AND status='claimed' AND lease_until!='' AND lease_until<?",
            (project_id, stamp_text),
        ).fetchall()
        for row in rows:
            db.execute(
                "UPDATE org_handling_orders SET status='queued',assignee_id=NULL,lease_until='',updated_at=? WHERE id=?",
                (stamp_text, row["id"]),
            )
            db.execute(
                "INSERT INTO org_order_transitions(order_id,project_id,from_status,to_status,actor_id,note,created_at) "
                "VALUES(?,?, 'claimed','queued',NULL,?,?)",
                (row["id"], project_id, "lease_expired", stamp_text),
            )
            self.audit("order.lease_expire", project_id, row["assignee_id"], "handling_order", str(row["id"]),
                       {"order_no": row["order_no"], "lease_until": row["lease_until"]})

    def _require_handling_role(self, project_id: int, user: sqlite3.Row) -> str:
        return self.require_role(project_id, user["id"], HANDLING_ROLES)

    def claim_order(self, project_id: int, order_id: int, user: sqlite3.Row, note: str = "") -> dict[str, Any]:
        self._require_handling_role(project_id, user)
        stamp = now()
        lease_until = format_ts(add_minutes(now_dt(), LEASE_MINUTES))
        with transaction(immediate=True) as db:
            self._recover_expired(db, project_id)
            row = db.execute("SELECT * FROM org_handling_orders WHERE project_id=? AND id=?", (project_id, order_id)).fetchone()
            if row is None:
                raise ServiceError("order_not_found", "处置单不存在", 404)
            if row["status"] == "claimed":
                raise ServiceError("order_claimed", "处置单已被他人领取且租约未到期", 409)
            if row["status"] != "queued":
                raise ServiceError("order_not_claimable", "处置单当前状态不可领取", 409)
            db.execute(
                "UPDATE org_handling_orders SET status='claimed',assignee_id=?,lease_until=?,updated_at=? WHERE id=?",
                (user["id"], lease_until, stamp, order_id),
            )
            db.execute(
                "INSERT INTO org_order_transitions(order_id,project_id,from_status,to_status,actor_id,note,created_at) "
                "VALUES(?,?, 'queued','claimed',?,?,?)",
                (order_id, project_id, user["id"], note, stamp),
            )
            self.audit("order.claim", project_id, user["id"], "handling_order", str(order_id),
                       {"order_no": row["order_no"], "lease_until": lease_until})
            return self._order_view(db, db.execute("SELECT * FROM org_handling_orders WHERE id=?", (order_id,)).fetchone())

    def _owned_order(self, db: sqlite3.Connection, project_id: int, order_id: int, user: sqlite3.Row) -> sqlite3.Row:
        row = db.execute("SELECT * FROM org_handling_orders WHERE project_id=? AND id=?", (project_id, order_id)).fetchone()
        if row is None:
            raise ServiceError("order_not_found", "处置单不存在", 404)
        if row["status"] != "claimed" or row["assignee_id"] != user["id"]:
            raise ServiceError("order_not_owned", "只有当前领取人可以操作该处置单", 409)
        return row

    def complete_order(self, project_id: int, order_id: int, user: sqlite3.Row, note: str) -> dict[str, Any]:
        self._require_handling_role(project_id, user)
        stamp = now()
        with transaction(immediate=True) as db:
            row = self._owned_order(db, project_id, order_id, user)
            db.execute(
                "UPDATE org_handling_orders SET status='completed',lease_until='',result_note=?,updated_at=? WHERE id=?",
                (note, stamp, order_id),
            )
            db.execute(
                "INSERT INTO org_order_transitions(order_id,project_id,from_status,to_status,actor_id,note,created_at) "
                "VALUES(?,?, 'claimed','completed',?,?,?)",
                (order_id, project_id, user["id"], note, stamp),
            )
            for artifact_id in json.loads(row["artifact_ids_json"]):
                event = {
                    "lab_handover": "lab_handover",
                    "transfer": "transfer",
                    "repack": "repackage",
                }.get(row["kind"], "note")
                self._chain(project_id, artifact_id, event, user["id"], ref_type="handling_order", ref_id=str(order_id), detail={"result_note": note}, stamp=stamp)
            self.audit("order.complete", project_id, user["id"], "handling_order", str(order_id),
                       {"order_no": row["order_no"], "note": note})
            return self._order_view(db, db.execute("SELECT * FROM org_handling_orders WHERE id=?", (order_id,)).fetchone())

    def return_order(self, project_id: int, order_id: int, user: sqlite3.Row, note: str) -> dict[str, Any]:
        self._require_handling_role(project_id, user)
        if not note.strip():
            raise ServiceError("note_required", "退回处置单必须填写退回原因", 422)
        stamp = now()
        with transaction(immediate=True) as db:
            row = self._owned_order(db, project_id, order_id, user)
            db.execute(
                "UPDATE org_handling_orders SET status='queued',assignee_id=NULL,lease_until='',updated_at=? WHERE id=?",
                (stamp, order_id),
            )
            db.execute(
                "INSERT INTO org_order_transitions(order_id,project_id,from_status,to_status,actor_id,note,created_at) "
                "VALUES(?,?, 'claimed','queued',?,?,?)",
                (order_id, project_id, user["id"], note, stamp),
            )
            for artifact_id in json.loads(row["artifact_ids_json"]):
                self._chain(project_id, artifact_id, "return", user["id"],
                            ref_type="handling_order", ref_id=str(order_id), detail={"note": note}, stamp=stamp)
            self.audit("order.return", project_id, user["id"], "handling_order", str(order_id),
                       {"order_no": row["order_no"], "note": note})
            return self._order_view(db, db.execute("SELECT * FROM org_handling_orders WHERE id=?", (order_id,)).fetchone())

    def transfer_order(self, project_id: int, order_id: int, user: sqlite3.Row, to_username: str | None, note: str) -> dict[str, Any]:
        self._require_handling_role(project_id, user)
        if not to_username:
            raise ServiceError("assignee_required", "转交必须指定目标保护人员", 422)
        target = self.db.execute("SELECT * FROM users WHERE username=? AND status='active'", (to_username,)).fetchone()
        if target is None:
            raise ServiceError("assignee_not_found", "目标用户不存在", 404)
        target_role = self.db.execute(
            "SELECT role FROM project_members WHERE project_id=? AND user_id=?", (project_id, target["id"])
        ).fetchone()
        if target_role is None or target_role["role"] not in HANDLING_ROLES:
            raise ServiceError("assignee_not_allowed", "目标用户不是该项目的保护人员", 403)
        stamp = now()
        lease_until = format_ts(add_minutes(now_dt(), LEASE_MINUTES))
        with transaction(immediate=True) as db:
            row = self._owned_order(db, project_id, order_id, user)
            if target["id"] == user["id"]:
                raise ServiceError("invalid_transfer", "不能转交给自己", 422)
            db.execute(
                "UPDATE org_handling_orders SET assignee_id=?,lease_until=?,updated_at=? WHERE id=?",
                (target["id"], lease_until, stamp, order_id),
            )
            db.execute(
                "INSERT INTO org_order_transitions(order_id,project_id,from_status,to_status,actor_id,note,created_at) "
                "VALUES(?,?, 'claimed','claimed',?,?,?)",
                (order_id, project_id, user["id"], stable_json({"to_user_id": target["id"], "to_username": to_username, "note": note}), stamp),
            )
            self.audit("order.transfer", project_id, user["id"], "handling_order", str(order_id),
                       {"order_no": row["order_no"], "to_username": to_username, "note": note})
            return self._order_view(db, db.execute("SELECT * FROM org_handling_orders WHERE id=?", (order_id,)).fetchone())

    def _order_view(self, db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        assignee = None
        if row["assignee_id"] is not None:
            user_row = db.execute("SELECT username,display_name FROM users WHERE id=?", (row["assignee_id"],)).fetchone()
            if user_row is not None:
                assignee = {"id": row["assignee_id"], "username": user_row["username"], "display_name": user_row["display_name"]}
        data["assignee"] = assignee
        data["artifact_ids"] = json.loads(row["artifact_ids_json"])
        del data["artifact_ids_json"]
        transitions = db.execute(
            "SELECT t.*, u.username AS actor_username FROM org_order_transitions t "
            "LEFT JOIN users u ON u.id=t.actor_id WHERE t.order_id=? ORDER BY t.id",
            (row["id"],),
        ).fetchall()
        data["transitions"] = [dict(item) for item in transitions]
        return data

    def list_orders(self, project_id: int, user: sqlite3.Row, status_filter: str | None = None) -> dict[str, Any]:
        self.require_any_member(project_id, user["id"])
        with transaction(immediate=True) as db:
            self._recover_expired(db, project_id)
            sql = "SELECT * FROM org_handling_orders WHERE project_id=?"
            params: list[Any] = [project_id]
            if status_filter:
                sql += " AND status=?"
                params.append(status_filter)
            sql += " ORDER BY id"
            rows = db.execute(sql, params).fetchall()
            return {"data": [self._order_view(db, row) for row in rows]}

    def get_order(self, project_id: int, order_id: int, user: sqlite3.Row) -> dict[str, Any]:
        self.require_any_member(project_id, user["id"])
        with transaction(immediate=True) as db:
            self._recover_expired(db, project_id)
            row = db.execute("SELECT * FROM org_handling_orders WHERE project_id=? AND id=?", (project_id, order_id)).fetchone()
            if row is None:
                raise ServiceError("order_not_found", "处置单不存在", 404)
            return self._order_view(db, row)
