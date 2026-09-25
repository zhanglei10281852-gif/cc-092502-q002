"""有机遗物模块端到端测试。

覆盖：库位脱敏与角色鉴权、阈值版本化、越界去重与按时长升级、
乱序补点、重复批次确定性重放、跨日维护窗口抑制缺测、处置单租约
（含到期恢复与转交）、合包/拆包链路、失败事务回滚与审计。
"""

from __future__ import annotations

import pytest

from app.database import connection


@pytest.fixture()
def world(client, owner):
    project = client.post(
        "/api/projects",
        json={"code": "ORG1", "name": "有机遗物保护", "site_name": "溧阳鲍家遗址"},
        headers=owner["headers"],
    ).json()
    pid = project["id"]

    def make_user(username: str, display: str, password: str, role: str | None):
        client.post("/api/users", json={"username": username, "display_name": display, "password": password})
        login = client.post("/api/sessions", json={"username": username, "password": password}).json()
        headers = {"Authorization": f"Bearer {login['token']}"}
        if role:
            uid = login["user_id"]
            r = client.post(f"/api/projects/{pid}/members", json={"user_id": uid, "role": role}, headers=owner["headers"])
            assert r.status_code == 200, r.text
        return {"headers": headers, "user_id": login["user_id"]}

    cons = make_user("cons", "保护师甲", "ConsPass!2345", "conservator")
    cons2 = make_user("cons2", "保护师乙", "Cons2Pass!234", "conservator")
    rec = make_user("rec", "库房登记员", "RecPass!23456", "recorder")
    viewer = make_user("viewer", "观摩员", "ViewPass!2345", "viewer")

    return {
        "client": client,
        "pid": pid,
        "owner": owner,
        "cons": cons,
        "cons2": cons2,
        "rec": rec,
        "viewer": viewer,
    }


WOOD_SCHEME = {
    "material_kind": "wood",
    "rules": [
        {"metric": "temperature", "min_value": 2.0, "max_value": 8.0,
         "escalate_after_minutes": 30, "critical_after_minutes": 120},
    ],
}


def register(client, pid, headers, number="T-0001", location="A-01", material="wood"):
    return client.post(
        f"/api/projects/{pid}/artifacts",
        json={
            "temp_number": number,
            "material_kind": material,
            "burial_env": "saturated_silt",
            "storage_state": "immersed",
            "container_code": f"C-{number}",
            "immersion_fluid": "去离子水",
            "location_code": location,
        },
        headers=headers,
    )


# ------------------------------------------------------------ 注册与库位脱敏

def test_register_requires_role_and_masks_location(world):
    client, pid = world["client"], world["pid"]
    denied = register(client, pid, world["viewer"]["headers"], number="T-X")
    assert denied.status_code == 403

    ok = register(client, pid, world["rec"]["headers"])
    assert ok.status_code == 201
    assert ok.json()["location_code"] == "A-01"

    as_viewer = client.get(f"/api/projects/{pid}/artifacts/T-0001", headers=world["viewer"]["headers"])
    assert as_viewer.json()["location_code"] == "***"

    as_cons = client.get(f"/api/projects/{pid}/artifacts/T-0001", headers=world["cons"]["headers"])
    assert as_cons.json()["location_code"] == "A-01"

    alerts_view = client.get(f"/api/projects/{pid}/alerts", headers=world["viewer"]["headers"])
    assert alerts_view.status_code == 200


def test_duplicate_temp_number_conflict(world):
    client, pid = world["client"], world["pid"]
    assert register(client, pid, world["rec"]["headers"]).status_code == 201
    dup = register(client, pid, world["rec"]["headers"])
    assert dup.status_code == 409
    assert dup.json()["error"]["code"] == "artifact_exists"


# --------------------------------------------------------------- 阈值版本化

def test_threshold_scheme_versioning_and_permission(world):
    client, pid = world["client"], world["pid"]
    assert client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["rec"]["headers"]).status_code == 403

    v1 = client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])
    assert v1.status_code == 201 and v1.json()["version"] == 1

    scheme2 = {"material_kind": "wood", "rules": [
        {"metric": "temperature", "min_value": 3.0, "max_value": 7.0,
         "escalate_after_minutes": 30, "critical_after_minutes": 120}
    ]}
    v2 = client.post(f"/api/projects/{pid}/threshold-schemes", json=scheme2, headers=world["cons"]["headers"])
    assert v2.json()["version"] == 2

    schemes = client.get(f"/api/projects/{pid}/threshold-schemes?material_kind=wood", headers=world["viewer"]["headers"]).json()["data"]
    assert [row["version"] for row in schemes] == [1, 2]
    assert [row["active"] for row in schemes] == [False, True]


# ------------------------------------------------- 越界去重、升级与批次重放

def test_alert_dedup_escalation_and_replay(world):
    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"])
    client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])

    batch = {
        "batch_ref": "B1",
        "readings": [
            {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:00:00Z"},
            {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.4, "measured_at": "2026-09-25T00:10:00Z"},
            {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.1, "measured_at": "2026-09-25T00:40:00Z"},
        ],
    }
    first = client.post(f"/api/projects/{pid}/sensor-batches", json=batch, headers=world["rec"]["headers"])
    assert first.status_code == 201
    summary = first.json()
    assert len(summary["alerts"]) == 1
    alert = summary["alerts"][0]
    assert alert["violation_kind"] == "high"
    assert alert["level"] == "serious" and alert["status"] == "escalated"
    assert len(summary["todos"]) == 1 and summary["todos"][0]["priority"] == "high"

    # 确定性重放：同批次同内容返回既有结果，不新增告警/待办
    replay = client.post(f"/api/projects/{pid}/sensor-batches", json=batch, headers=world["rec"]["headers"])
    assert replay.status_code == 201 and replay.json()["replayed"] is True
    assert replay.json()["alerts"] == summary["alerts"]
    assert replay.json()["todos"] == summary["todos"]

    # 同批次号不同内容必须拒绝
    conflict = client.post(f"/api/projects/{pid}/sensor-batches",
                           json={"batch_ref": "B1", "readings": [
                               {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 5.0,
                                "measured_at": "2026-09-25T01:00:00Z"}]},
                           headers=world["rec"]["headers"])
    assert conflict.status_code == 409

    # 重复读数（同遗物/指标/时刻）计数为 duplicate，不新增告警
    dup_batch = {
        "batch_ref": "B2",
        "readings": [
            {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:00:00Z"},
            {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.2, "measured_at": "2026-09-25T00:50:00Z"},
        ],
    }
    dup = client.post(f"/api/projects/{pid}/sensor-batches", json=dup_batch, headers=world["rec"]["headers"]).json()
    assert dup["readings_received"] == 2
    assert dup["readings_imported"] == 1
    assert dup["duplicates"] == 1
    # 仍然只有同一条越界告警
    open_alerts = client.get(f"/api/projects/{pid}/alerts", headers=world["cons"]["headers"]).json()["data"]
    assert len(open_alerts) == 1


def test_out_of_order_backfill_merges_then_splits_alert(world):
    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"])
    client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])

    def imp(ref, rows):
        return client.post(f"/api/projects/{pid}/sensor-batches",
                           json={"batch_ref": ref, "readings": rows},
                           headers=world["rec"]["headers"]).json()

    imp("A", [
        {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:00:00Z"},
        {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:40:00Z"},
    ])
    # 乱序补点（更早的时刻后到），同方向并入同一段，不产生新告警
    imp("B", [
        {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:10:00Z"},
        {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 9.0, "measured_at": "2026-09-25T00:20:00Z"},
    ])
    alerts = client.get(f"/api/projects/{pid}/alerts", headers=world["cons"]["headers"]).json()["data"]
    assert len(alerts) == 1 and alerts[0]["level"] == "serious"

    # 再补一个正常读数把越界段切成两段：前段关闭，后段开放
    imp("C", [
        {"artifact_temp_number": "T-0001", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-25T00:05:00Z"},
    ])
    alerts = client.get(f"/api/projects/{pid}/alerts", headers=world["cons"]["headers"]).json()["data"]
    by_status = {row["status"]: row for row in alerts}
    assert set(by_status) == {"resolved", "escalated"}
    assert by_status["resolved"]["first_reading_at"].startswith("2026-09-25T00:00:00")
    assert by_status["escalated"]["first_reading_at"].startswith("2026-09-25T00:10:00")


# ----------------------------------------------------------- 缺测与维护窗口

def test_missing_reading_suppressed_in_cross_day_window(world):
    client, pid = world["client"], world["pid"]
    scheme = {"material_kind": "wood", "rules": [
        {"metric": "temperature", "min_value": 2.0, "max_value": 8.0,
         "escalate_after_minutes": 30, "critical_after_minutes": 120,
         "expect_interval_minutes": 10}
    ]}
    register(client, pid, world["rec"]["headers"], number="T-X", location="L-X")
    register(client, pid, world["rec"]["headers"], number="T-Y", location="L-Y")
    client.post(f"/api/projects/{pid}/threshold-schemes", json=scheme, headers=world["cons"]["headers"])

    win = client.post(f"/api/projects/{pid}/maintenance-windows", json={
        "start_at": "2026-09-25T23:00:00Z",
        "end_at": "2026-09-26T01:00:00Z",
        "location_code": "L-X",
        "reason": "夜间换液",
    }, headers=world["rec"]["headers"])
    assert win.status_code == 201

    batch = {
        "batch_ref": "M1",
        "readings": [
            # X 的缺口跨午夜且完全落在维护窗口内 → 不报缺测
            {"artifact_temp_number": "T-X", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-25T23:50:00Z"},
            {"artifact_temp_number": "T-X", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-26T00:20:00Z"},
            # Y 的缺口无维护窗口 → 缺测 40 分钟，serious
            {"artifact_temp_number": "T-Y", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-25T02:00:00Z"},
            {"artifact_temp_number": "T-Y", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-25T02:40:00Z"},
        ],
    }
    summary = client.post(f"/api/projects/{pid}/sensor-batches", json=batch, headers=world["rec"]["headers"]).json()
    missing = [a for a in summary["alerts"] if a["violation_kind"] == "missing"]
    assert len(missing) == 1
    assert missing[0]["level"] == "serious"
    assert missing[0]["artifact_id"] != summary["alerts"][0]["artifact_id"] or missing[0]["metric"]
    assert any(t["priority"] == "high" for t in summary["todos"])


# ----------------------------------------------------------- 处置单与租约

def test_handling_order_permissions_transfer_and_expiry(world):
    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"])

    order = client.post(f"/api/projects/{pid}/handling-orders", json={
        "order_no": "HO-1", "kind": "lab_handover", "artifact_temp_numbers": ["T-0001"], "reason": "送检"},
        headers=world["rec"]["headers"])
    assert order.status_code == 201
    oid = order.json()["id"]

    # 登记员/观摩员不能领取
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["rec"]["headers"]).status_code == 403
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["viewer"]["headers"]).status_code == 403

    claimed = client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={"note": "领取"}, headers=world["cons"]["headers"])
    assert claimed.status_code == 200
    assert claimed.json()["assignee"]["username"] == "cons"
    assert claimed.json()["lease_until"]

    # 他人不能重复领取，也不能完成
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["cons2"]["headers"]).status_code == 409
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/complete", json={"note": "done"}, headers=world["cons2"]["headers"]).status_code == 409

    # 转交：缺目标 422；转给非保护人员 403；正常转交成功
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/transfer", json={}, headers=world["cons"]["headers"]).status_code == 422
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/transfer", json={"to_username": "viewer"}, headers=world["cons"]["headers"]).status_code == 403
    moved = client.post(f"/api/projects/{pid}/handling-orders/{oid}/transfer", json={"to_username": "cons2", "note": "换人"}, headers=world["cons"]["headers"])
    assert moved.status_code == 200 and moved.json()["assignee"]["username"] == "cons2"

    # 租约到期（模拟停机后时钟越过 lease_until），重新进入队列并可被领取
    connection().execute("UPDATE org_handling_orders SET lease_until='2000-01-01T00:00:00+0000' WHERE id=?", (oid,))
    connection().commit()
    listing = client.get(f"/api/projects/{pid}/handling-orders", headers=world["owner"]["headers"]).json()["data"]
    queued = next(row for row in listing if row["id"] == oid)
    assert queued["status"] == "queued" and queued["assignee"] is None
    transitions = client.get(f"/api/projects/{pid}/handling-orders/{oid}", headers=world["cons"]["headers"]).json()["transitions"]
    assert any(row["note"] == "lease_expired" for row in transitions)

    reclaimed = client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["cons"]["headers"])
    assert reclaimed.status_code == 200
    done = client.post(f"/api/projects/{pid}/handling-orders/{oid}/complete", json={"note": "交接完成"}, headers=world["cons"]["headers"])
    assert done.status_code == 200 and done.json()["status"] == "completed"


def test_return_order_requires_note(world):
    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"], number="T-R1")
    oid = client.post(f"/api/projects/{pid}/handling-orders",
                      json={"order_no": "HO-R", "kind": "transfer", "artifact_temp_numbers": ["T-R1"]},
                      headers=world["rec"]["headers"]).json()["id"]
    client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["cons"]["headers"])
    assert client.post(f"/api/projects/{pid}/handling-orders/{oid}/return", json={}, headers=world["cons"]["headers"]).status_code == 422
    back = client.post(f"/api/projects/{pid}/handling-orders/{oid}/return", json={"note": "包装破损，退回"}, headers=world["cons"]["headers"])
    assert back.status_code == 200 and back.json()["status"] == "queued"


# ------------------------------------------------------------- 合包/拆包链路

def test_merge_split_packages_preserves_chain(world):
    client, pid = world["client"], world["pid"]
    for number in ("T-1", "T-2", "T-3"):
        assert register(client, pid, world["rec"]["headers"], number=number, location="B-1").status_code == 201

    p1 = client.post(f"/api/projects/{pid}/packages", json={"package_code": "P1", "artifact_temp_numbers": ["T-1", "T-2"]}, headers=world["rec"]["headers"])
    p2 = client.post(f"/api/projects/{pid}/packages", json={"package_code": "P2", "artifact_temp_numbers": ["T-3"]}, headers=world["rec"]["headers"])
    assert p1.status_code == 201 and p2.status_code == 201

    merged = client.post(f"/api/projects/{pid}/packages/merge",
                         json={"source_package_codes": ["P1", "P2"], "target_package_code": "P3"},
                         headers=world["rec"]["headers"])
    assert merged.status_code == 201
    assert {item["temp_number"] for item in merged.json()["items"]} == {"T-1", "T-2", "T-3"}

    # 失败事务：拆分未覆盖全部遗物 → 409，且 P4 不落库、P3 仍可用
    bad = client.post(f"/api/projects/{pid}/packages/split", json={
        "source_package_code": "P3",
        "target_package_codes": ["P4"],
        "groups": [["T-1"]],
    }, headers=world["rec"]["headers"])
    assert bad.status_code == 409
    pkg = client.get(f"/api/projects/{pid}/packages/P3", headers=world["cons"]["headers"]).json()
    assert pkg["status"] == "active"
    assert client.get(f"/api/projects/{pid}/packages/P4", headers=world["cons"]["headers"]).status_code == 404

    split = client.post(f"/api/projects/{pid}/packages/split", json={
        "source_package_code": "P3",
        "target_package_codes": ["P4", "P5"],
        "groups": [["T-1"], ["T-2", "T-3"]],
    }, headers=world["rec"]["headers"])
    assert split.status_code == 201

    chain = client.get(f"/api/projects/{pid}/artifacts/T-1/chain", headers=world["cons"]["headers"]).json()["data"]
    types = [(row["event_type"], row["from_package_code"], row["to_package_code"]) for row in chain]
    assert ("register", None, None) in types
    assert ("repackage", None, "P1") in types
    assert ("merge", "P1", "P3") in types
    assert ("split", "P3", "P4") in types
    # 链路顺序严格递增
    assert [row["id"] for row in chain] == sorted(row["id"] for row in chain)


# ------------------------------------------------------------- 失败事务回滚

def test_batch_with_unknown_artifact_rolls_back(world):
    client, pid = world["client"], world["pid"]
    client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])
    before_batches = connection().execute("SELECT COUNT(*) FROM org_sensor_batches WHERE project_id=?", (pid,)).fetchone()[0]
    bad = client.post(f"/api/projects/{pid}/sensor-batches", json={
        "batch_ref": "BAD1",
        "readings": [
            {"artifact_temp_number": "GHOST", "metric": "temperature", "value": 5.0, "measured_at": "2026-09-25T00:00:00Z"},
        ],
    }, headers=world["rec"]["headers"])
    assert bad.status_code == 404
    after_batches = connection().execute("SELECT COUNT(*) FROM org_sensor_batches WHERE project_id=?", (pid,)).fetchone()[0]
    after_readings = connection().execute("SELECT COUNT(*) FROM org_sensor_readings WHERE project_id=?", (pid,)).fetchone()[0]
    assert before_batches == after_batches == 0
    assert after_readings == 0


def test_failure_mid_transaction_rolls_everything_back(world, monkeypatch):
    # 批次、读数、告警都已在事务内写入后，待办生成阶段抛错：
    # 整笔事务必须回滚，不留任何批次、读数、告警、待办或审计。
    from app.organics.service import OrganicService, ServiceError as OrganicServiceError

    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"], number="T-FAIL")
    client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])

    def boom(self, *args, **kwargs):
        raise OrganicServiceError("simulated_failure", "模拟待办阶段失败", 500)

    monkeypatch.setattr(OrganicService, "_ensure_todo", boom)
    response = client.post(f"/api/projects/{pid}/sensor-batches", json={
        "batch_ref": "FAILX",
        "readings": [
            {"artifact_temp_number": "T-FAIL", "metric": "temperature", "value": 9.5, "measured_at": "2026-09-25T00:00:00Z"},
            {"artifact_temp_number": "T-FAIL", "metric": "temperature", "value": 9.6, "measured_at": "2026-09-25T00:40:00Z"},
        ],
    }, headers=world["rec"]["headers"])
    assert response.status_code == 500

    db = connection()
    assert db.execute("SELECT COUNT(*) FROM org_sensor_batches WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM org_sensor_readings WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM org_alerts WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM org_handling_orders WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM audit_events WHERE project_id=? AND action LIKE 'alert.%'", (pid,)).fetchone()[0] == 0

    # 崩溃后服务恢复正常：同样的数据可以完整导入
    monkeypatch.undo()
    ok = client.post(f"/api/projects/{pid}/sensor-batches", json={
        "batch_ref": "FAILX",
        "readings": [
            {"artifact_temp_number": "T-FAIL", "metric": "temperature", "value": 9.5, "measured_at": "2026-09-25T00:00:00Z"},
            {"artifact_temp_number": "T-FAIL", "metric": "temperature", "value": 9.6, "measured_at": "2026-09-25T00:40:00Z"},
        ],
    }, headers=world["rec"]["headers"])
    assert ok.status_code == 201
    assert len(ok.json()["alerts"]) == 1 and len(ok.json()["todos"]) == 1


def test_audit_records_threshold_order_and_handoff(world):
    client, pid = world["client"], world["pid"]
    register(client, pid, world["rec"]["headers"], number="T-A9")
    client.post(f"/api/projects/{pid}/threshold-schemes", json=WOOD_SCHEME, headers=world["cons"]["headers"])
    oid = client.post(f"/api/projects/{pid}/handling-orders",
                      json={"order_no": "HO-A", "kind": "lab_handover", "artifact_temp_numbers": ["T-A9"]},
                      headers=world["rec"]["headers"]).json()["id"]
    client.post(f"/api/projects/{pid}/handling-orders/{oid}/claim", json={}, headers=world["cons"]["headers"])
    client.post(f"/api/projects/{pid}/handling-orders/{oid}/complete", json={"note": "完成交接"}, headers=world["cons"]["headers"])

    audit = client.get(f"/api/audit?project_id={pid}", headers=world["owner"]["headers"]).json()["data"]
    actions = [row["action"] for row in audit]
    for expected in ("threshold.scheme_publish", "order.create", "order.claim", "order.complete"):
        assert expected in actions
    # 实验室交接进入遗物链路
    chain = client.get(f"/api/projects/{pid}/artifacts/T-A9/chain", headers=world["cons"]["headers"]).json()["data"]
    assert any(row["event_type"] == "lab_handover" for row in chain)
