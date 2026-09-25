from __future__ import annotations

import json

import pytest

from app.conservation import ConservationService
from app.database import close_connection, connection

PASSWORD = "ConservPass!234"

WOOD_SCHEME = {
    "metrics": {
        "temperature": {"min": 2.0, "max": 8.0},
        "humidity": {"min": 90.0, "max": 100.0},
        "ph": {"min": 6.5, "max": 7.5},
    },
    "missing_after_minutes": 180,
    "escalation": [
        {"after_minutes": 60, "severity": "elevated"},
        {"after_minutes": 120, "severity": "critical"},
    ],
}


def url(project_id: int, path: str) -> str:
    return f"/api/projects/{project_id}/conservation{path}"


def make_user(client, username: str) -> dict:
    response = client.post("/api/users", json={"username": username, "display_name": username, "password": PASSWORD})
    assert response.status_code == 201
    return response.json()


def login(client, username: str) -> dict:
    response = client.post("/api/sessions", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture()
def project(client, owner):
    response = client.post("/api/projects", json={"code": "CONS", "name": "有机遗物保护", "site_name": "遗址"}, headers=owner["headers"])
    assert response.status_code == 201
    return response.json()


@pytest.fixture()
def team(client, owner, project):
    pid = project["id"]
    people = {}
    for username, role in [("conservator", "conservator"), ("conservator2", "conservator"), ("recorder", "recorder"), ("viewer", "viewer")]:
        user = make_user(client, username)
        response = client.post(f"/api/projects/{pid}/members", json={"user_id": user["id"], "role": role}, headers=owner["headers"])
        assert response.status_code == 200
        people[username] = {"user": user, "headers": login(client, username)}
    return people


def publish_scheme(client, owner, project_id: int, config: dict | None = None, category: str = "wood"):
    response = client.post(
        url(project_id, "/thresholds"),
        json={"category": category, "config": config or WOOD_SCHEME},
        headers=owner["headers"],
    )
    assert response.status_code == 201
    return response.json()


def make_container(client, owner, project_id: int, code: str = "TANK-1", category: str = "wood", sensitive: bool = False) -> dict:
    location_id = None
    if sensitive:
        location = client.post(
            url(project_id, "/locations"),
            json={"code": "VAULT", "name": "恒温恒湿库房", "sensitive": True},
            headers=owner["headers"],
        )
        assert location.status_code == 201
        location_id = location.json()["id"]
    response = client.post(
        url(project_id, "/containers"),
        json={"code": code, "kind": "soak_tank", "category": category, "location_id": location_id},
        headers=owner["headers"],
    )
    assert response.status_code == 201
    return response.json()


def register(client, headers, project_id: int, temp_number: str, container_code: str | None = None, category: str = "wood") -> dict:
    payload = {
        "temp_number": temp_number,
        "category": category,
        "material_note": "饱水有机质",
        "excavation_env": "深埋饱水淤泥",
    }
    if container_code:
        payload["container_code"] = container_code
    response = client.post(url(project_id, "/artifacts"), json=payload, headers=headers)
    assert response.status_code == 201
    return response.json()


def import_batch(client, headers, project_id: int, batch_key: str, readings: list[dict], as_of: str | None = None):
    payload: dict = {"batch_key": batch_key, "readings": readings}
    if as_of:
        payload["as_of"] = as_of
    response = client.post(url(project_id, "/sensor-batches"), json=payload, headers=headers)
    assert response.status_code == 201
    return response.json()


def temp_reading(container_code: str, value: float, observed_at: str) -> dict:
    return {"container_code": container_code, "metric": "temperature", "value": value, "observed_at": observed_at}


def alert_rows(project_id: int) -> list[dict]:
    rows = connection().execute("SELECT * FROM alerts WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
    return [dict(row) for row in rows]


def audit_actions(project_id: int) -> list[str]:
    rows = connection().execute("SELECT action FROM audit_events WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
    return [row[0] for row in rows]


# ---- 登记与敏感库位 ----
def test_registration_and_sensitive_location_masking(client, owner, project, team):
    pid = project["id"]
    container = make_container(client, owner, pid, sensitive=True)
    location_id = container["location_id"]
    artifact = register(client, team["recorder"]["headers"], pid, "LS-001", "TANK-1")
    assert artifact["status"] == "stored"
    assert artifact["container_code"] == "TANK-1"
    # 登记员不在敏感库位可见范围，写入响应同样脱敏
    assert artifact["location_id"] is None and artifact["location_hidden"] is True

    detail = client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=owner["headers"]).json()
    assert detail["location_id"] == location_id and detail["location_hidden"] is False

    masked = client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=team["viewer"]["headers"]).json()
    assert masked["location_id"] is None and masked["location_hidden"] is True

    locations = client.get(url(pid, "/locations"), headers=team["viewer"]["headers"]).json()["data"]
    assert locations[0]["code"] is None and locations[0]["hidden"] is True
    locations_owner = client.get(url(pid, "/locations"), headers=owner["headers"]).json()["data"]
    assert locations_owner[0]["code"] == "VAULT"

    custody = client.get(url(pid, f"/artifacts/{artifact['id']}/custody"), headers=team["viewer"]["headers"]).json()
    assert custody["events"][0]["event_type"] == "register"
    assert custody["events"][0]["to_location_id"] is None and custody["events"][0]["locations_hidden"] is True
    custody_owner = client.get(url(pid, f"/artifacts/{artifact['id']}/custody"), headers=owner["headers"]).json()
    assert custody_owner["events"][0]["to_location_id"] == location_id

    duplicate = client.post(
        url(pid, "/artifacts"),
        json={"temp_number": "LS-001", "category": "wood"},
        headers=team["recorder"]["headers"],
    )
    assert duplicate.status_code == 409
    assert "artifact.register" in audit_actions(pid)


def test_registration_rejects_category_mismatch(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid, code="TEXTILE-BOX", category="textile")
    response = client.post(
        url(pid, "/artifacts"),
        json={"temp_number": "LS-100", "category": "wood", "container_code": "TEXTILE-BOX"},
        headers=team["recorder"]["headers"],
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "category_mismatch"


# ---- 阈值方案版本化 ----
def test_threshold_versioning_and_validation(client, owner, project, team):
    pid = project["id"]
    first = publish_scheme(client, owner, pid)
    assert first["version"] == 1 and first["status"] == "active"

    invalid = client.post(url(pid, "/thresholds"), json={"category": "wood", "config": {"metrics": {}}}, headers=owner["headers"])
    assert invalid.status_code == 422

    non_monotonic = client.post(
        url(pid, "/thresholds"),
        json={
            "category": "wood",
            "config": {
                "metrics": {"temperature": {"max": 8.0}},
                "escalation": [
                    {"after_minutes": 60, "severity": "critical"},
                    {"after_minutes": 120, "severity": "elevated"},
                ],
            },
        },
        headers=owner["headers"],
    )
    assert non_monotonic.status_code == 400
    assert non_monotonic.json()["error"]["code"] == "invalid_scheme"

    forbidden = client.post(
        url(pid, "/thresholds"),
        json={"category": "wood", "config": WOOD_SCHEME},
        headers=team["recorder"]["headers"],
    )
    assert forbidden.status_code == 403

    updated = dict(WOOD_SCHEME)
    updated["metrics"] = {"temperature": {"min": 2.0, "max": 6.0}}
    second = publish_scheme(client, owner, pid, config=updated)
    assert second["version"] == 2 and second["status"] == "active"

    versions = client.get(url(pid, "/thresholds"), headers=team["viewer"]["headers"]).json()["data"]
    assert [(row["version"], row["status"]) for row in versions] == [(2, "active"), (1, "retired")]
    assert audit_actions(pid).count("threshold.publish") == 2


def test_new_scheme_applies_to_stored_readings(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    import_batch(client, team["recorder"]["headers"], pid, "b1", [temp_reading("TANK-1", 7.5, "2026-09-20T10:00:00+00:00")])
    assert alert_rows(pid) == []

    updated = dict(WOOD_SCHEME)
    updated["metrics"] = {"temperature": {"min": 2.0, "max": 6.0}}
    publish_scheme(client, owner, pid, config=updated)
    result = client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-20T10:30:00+00:00"}, headers=owner["headers"]).json()
    assert len(result["alerts"]["opened"]) == 1
    alerts = alert_rows(pid)
    assert alerts[0]["first_seen_at"] == "2026-09-20T10:00:00+00:00"
    assert alerts[0]["status"] == "open"


# ---- 告警去重、升级与缺测 ----
def test_alert_dedup_and_escalation_by_duration(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]

    first = import_batch(client, headers, pid, "b1", [
        temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"),
        temp_reading("TANK-1", 9.0, "2026-09-20T10:30:00+00:00"),
    ])
    assert len(first["alerts"]["opened"]) == 1
    alerts = alert_rows(pid)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "warning"
    assert alerts[0]["last_seen_at"] == "2026-09-20T10:30:00+00:00"

    second = import_batch(client, headers, pid, "b2", [temp_reading("TANK-1", 9.2, "2026-09-20T10:45:00+00:00")])
    assert second["alerts"]["opened"] == [] and second["alerts"]["escalated"] == []
    assert len(alert_rows(pid)) == 1

    escalated = client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-20T11:30:00+00:00"}, headers=owner["headers"]).json()
    assert len(escalated["alerts"]["escalated"]) == 1
    assert alert_rows(pid)[0]["severity"] == "elevated"

    client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-20T13:00:00+00:00"}, headers=owner["headers"])
    assert alert_rows(pid)[0]["severity"] == "critical"
    assert len(alert_rows(pid)) == 1

    import_batch(client, headers, pid, "b3", [temp_reading("TANK-1", 5.0, "2026-09-20T13:10:00+00:00")])
    alerts = alert_rows(pid)
    assert alerts[0]["status"] == "resolved"
    assert alerts[0]["resolved_at"] == "2026-09-20T13:10:00+00:00"
    assert alerts[0]["severity"] == "critical"
    actions = audit_actions(pid)
    assert actions.count("alert.escalate") == 2
    assert "alert.resolve" in actions


def test_missing_alert_opens_dedups_and_resolves(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    import_batch(client, headers, pid, "b1", [temp_reading("TANK-1", 5.0, "2026-09-20T10:00:00+00:00")])

    result = client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-20T13:30:00+00:00"}, headers=owner["headers"]).json()
    assert len(result["alerts"]["opened"]) == 1
    missing = [row for row in alert_rows(pid) if row["kind"] == "missing"]
    assert len(missing) == 1 and missing[0]["status"] == "open"

    client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-20T14:00:00+00:00"}, headers=owner["headers"])
    missing = [row for row in alert_rows(pid) if row["kind"] == "missing"]
    assert len(missing) == 1
    assert missing[0]["last_seen_at"] == "2026-09-20T14:00:00+00:00"

    import_batch(client, headers, pid, "b2", [temp_reading("TANK-1", 5.1, "2026-09-20T14:30:00+00:00")])
    missing = [row for row in alert_rows(pid) if row["kind"] == "missing"]
    assert missing[0]["status"] == "resolved"
    assert missing[0]["resolved_at"] == "2026-09-20T14:30:00+00:00"


def test_maintenance_window_cross_day_suppresses_missing(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid, code="TANK-A")
    make_container(client, owner, pid, code="TANK-B")
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    import_batch(client, headers, pid, "b1", [
        temp_reading("TANK-A", 5.0, "2026-09-25T17:00:00+00:00"),
        temp_reading("TANK-B", 5.0, "2026-09-25T17:00:00+00:00"),
    ])
    tank_a = client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"][0]
    window = client.post(
        url(pid, "/maintenance-windows"),
        json={"container_id": tank_a["id"], "starts_at": "2026-09-25T18:00:00+00:00", "ends_at": "2026-09-27T09:00:00+00:00", "reason": "跨日检修"},
        headers=owner["headers"],
    )
    assert window.status_code == 201

    def missing_for(code: str) -> list[dict]:
        rows = connection().execute(
            "SELECT a.* FROM alerts a JOIN containers c ON c.id=a.container_id WHERE a.project_id=? AND c.code=? AND a.kind='missing'",
            (pid, code),
        ).fetchall()
        return [dict(row) for row in rows]

    client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-26T12:00:00+00:00"}, headers=owner["headers"])
    assert missing_for("TANK-A") == []
    assert len(missing_for("TANK-B")) == 1

    client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-27T08:00:00+00:00"}, headers=owner["headers"])
    assert missing_for("TANK-A") == []

    client.post(url(pid, "/evaluate"), json={"as_of": "2026-09-27T13:00:00+00:00"}, headers=owner["headers"])
    assert len(missing_for("TANK-A")) == 1

    import_batch(client, headers, pid, "b2", [temp_reading("TANK-A", 4.8, "2026-09-27T13:30:00+00:00")])
    assert missing_for("TANK-A")[0]["status"] == "resolved"


# ---- 批次幂等与乱序确定性 ----
def test_duplicate_batch_is_idempotent(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    readings = [
        temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"),
        temp_reading("TANK-1", 9.0, "2026-09-20T10:30:00+00:00"),
    ]
    first = import_batch(client, headers, pid, "batch-x", readings)
    second = import_batch(client, headers, pid, "batch-x", readings)
    assert first["duplicate"] is False and second["duplicate"] is True
    assert first["alerts"] == second["alerts"]
    assert first["todos"] == second["todos"]
    assert connection().execute("SELECT COUNT(*) FROM sensor_readings WHERE project_id=?", (pid,)).fetchone()[0] == 2
    assert connection().execute("SELECT COUNT(*) FROM sensor_batches WHERE project_id=?", (pid,)).fetchone()[0] == 1
    assert len(alert_rows(pid)) == 1


def test_out_of_order_batches_converge(client, owner, project, team):
    pid = project["id"]
    other = client.post("/api/projects", json={"code": "CONS2", "name": "对照项目", "site_name": "遗址"}, headers=owner["headers"]).json()
    pid2 = other["id"]
    for project_id in (pid, pid2):
        make_container(client, owner, project_id)
        publish_scheme(client, owner, project_id)
    headers = team["recorder"]["headers"]
    bad_early = [temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"), temp_reading("TANK-1", 9.0, "2026-09-20T10:30:00+00:00")]
    good_late = [temp_reading("TANK-1", 5.0, "2026-09-20T11:00:00+00:00")]

    import_batch(client, headers, pid, "a1", bad_early)
    import_batch(client, headers, pid, "a2", good_late)
    import_batch(client, owner["headers"], pid2, "b1", good_late)
    import_batch(client, owner["headers"], pid2, "b2", bad_early)

    def signature(project_id: int) -> list[tuple]:
        return [
            (row["metric"], row["kind"], row["severity"], row["status"], row["first_seen_at"], row["last_seen_at"], row["resolved_at"])
            for row in alert_rows(project_id)
        ]

    assert signature(pid) == signature(pid2)
    assert signature(pid) == [("temperature", "threshold", "elevated", "resolved", "2026-09-20T10:00:00+00:00", "2026-09-20T10:30:00+00:00", "2026-09-20T11:00:00+00:00")]


def test_late_reading_splits_and_extends_episode(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    import_batch(client, headers, pid, "b1", [
        temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"),
        temp_reading("TANK-1", 9.0, "2026-09-20T11:00:00+00:00"),
    ])
    alerts = alert_rows(pid)
    assert len(alerts) == 1 and alerts[0]["status"] == "open"

    # 乱序到达的正常读数把越界片段切成两段：前段解除，尾段形成新告警
    split = import_batch(client, headers, pid, "b2", [temp_reading("TANK-1", 5.0, "2026-09-20T10:30:00+00:00")])
    assert len(split["alerts"]["resolved"]) == 1 and len(split["alerts"]["opened"]) == 1
    assert {(row["status"], row["first_seen_at"]) for row in alert_rows(pid)} == {
        ("resolved", "2026-09-20T10:00:00+00:00"),
        ("open", "2026-09-20T11:00:00+00:00"),
    }

    # 更早的越界读数迟到，把片段起点向前延伸：旧告警收回，新告警以更早起点生成
    extended = import_batch(client, headers, pid, "b3", [temp_reading("TANK-1", 9.1, "2026-09-20T09:30:00+00:00")])
    assert len(extended["alerts"]["retracted"]) == 1
    assert len(extended["alerts"]["opened"]) == 1
    alerts = alert_rows(pid)
    assert len(alerts) == 2
    resolved = [row for row in alerts if row["status"] == "resolved"]
    assert resolved[0]["first_seen_at"] == "2026-09-20T09:30:00+00:00"
    assert resolved[0]["resolved_at"] == "2026-09-20T10:30:00+00:00"


# ---- 失败事务回滚 ----
def test_failed_batch_rolls_back(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    response = client.post(
        url(pid, "/sensor-batches"),
        json={
            "batch_key": "bad-batch",
            "readings": [
                temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"),
                temp_reading("NO-SUCH-TANK", 9.5, "2026-09-20T10:00:00+00:00"),
            ],
        },
        headers=team["recorder"]["headers"],
    )
    assert response.status_code == 404
    assert connection().execute("SELECT COUNT(*) FROM sensor_batches WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert connection().execute("SELECT COUNT(*) FROM sensor_readings WHERE project_id=?", (pid,)).fetchone()[0] == 0
    assert alert_rows(pid) == []


# ---- 合并拆分与链路 ----
def test_merge_split_preserves_custody_chain(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid, code="BOX-A")
    make_container(client, owner, pid, code="BOX-B")
    make_container(client, owner, pid, code="BOX-C")
    headers = team["recorder"]["headers"]
    a1 = register(client, headers, pid, "LS-001", "BOX-A")
    a2 = register(client, headers, pid, "LS-002", "BOX-A")
    a3 = register(client, headers, pid, "LS-003", "BOX-B")
    containers = {row["code"]: row["id"] for row in client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"]}

    merged = client.post(
        url(pid, f"/containers/{containers['BOX-C']}/merge"),
        json={"source_container_ids": [containers["BOX-A"], containers["BOX-B"]], "note": "集中浸泡"},
        headers=headers,
    )
    assert merged.status_code == 200 and merged.json()["moved"] == 3
    states = {row["code"]: row["status"] for row in client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"]}
    assert states["BOX-A"] == states["BOX-B"] == "merged" and states["BOX-C"] == "active"

    split = client.post(
        url(pid, f"/containers/{containers['BOX-C']}/split"),
        json={"artifact_ids": [a1["id"], a3["id"]], "new_container": {"code": "BOX-D", "kind": "sealed_box"}, "note": "分送实验室"},
        headers=headers,
    )
    assert split.status_code == 200 and split.json()["moved"] == 2

    custody = client.get(url(pid, f"/artifacts/{a1['id']}/custody"), headers=owner["headers"]).json()
    assert [event["event_type"] for event in custody["events"]] == ["register", "merge", "split"]
    assert custody["events"][1]["from_container_id"] == containers["BOX-A"]
    assert custody["events"][1]["to_container_id"] == containers["BOX-C"]
    assert custody["events"][2]["to_container_id"] == split.json()["new_container_id"]
    assert custody["artifact"]["container_code"] == "BOX-D"

    custody_a2 = client.get(url(pid, f"/artifacts/{a2['id']}/custody"), headers=owner["headers"]).json()
    assert [event["event_type"] for event in custody_a2["events"]] == ["register", "merge"]
    assert custody_a2["artifact"]["container_code"] == "BOX-C"
    assert "container.merge" in audit_actions(pid) and "container.split" in audit_actions(pid)


def test_failed_merge_rolls_back(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid, code="BOX-W", category="wood")
    make_container(client, owner, pid, code="BOX-T", category="textile")
    make_container(client, owner, pid, code="BOX-TARGET", category="wood")
    headers = team["recorder"]["headers"]
    artifact = register(client, headers, pid, "LS-200", "BOX-W")
    containers = {row["code"]: row["id"] for row in client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"]}

    mismatch = client.post(
        url(pid, f"/containers/{containers['BOX-TARGET']}/merge"),
        json={"source_container_ids": [containers["BOX-W"], containers["BOX-T"]]},
        headers=headers,
    )
    assert mismatch.status_code == 400
    detail = client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=owner["headers"]).json()
    assert detail["container_code"] == "BOX-W"
    states = {row["code"]: row["status"] for row in client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"]}
    assert states["BOX-W"] == states["BOX-T"] == "active"

    split = client.post(
        url(pid, f"/containers/{containers['BOX-W']}/split"),
        json={"artifact_ids": [artifact["id"] + 999], "new_container": {"code": "BOX-X"}},
        headers=headers,
    )
    assert split.status_code == 404
    codes = {row["code"] for row in client.get(url(pid, "/containers"), headers=owner["headers"]).json()["data"]}
    assert "BOX-X" not in codes


# ---- 处置单 ----
def test_treatment_order_lifecycle_and_audit(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    artifact = register(client, team["recorder"]["headers"], pid, "LS-300", "TANK-1")
    conservator = team["conservator"]["user"]
    conservator2 = team["conservator2"]["user"]

    denied = client.post(
        url(pid, "/treatment-orders"),
        json={"artifact_id": artifact["id"], "order_type": "wet_storage", "title": "湿存检查", "assignee_id": conservator["id"]},
        headers=team["recorder"]["headers"],
    )
    assert denied.status_code == 403

    bad_assignee = client.post(
        url(pid, "/treatment-orders"),
        json={"artifact_id": artifact["id"], "order_type": "wet_storage", "title": "湿存检查", "assignee_id": team["recorder"]["user"]["id"]},
        headers=owner["headers"],
    )
    assert bad_assignee.status_code == 400

    order = client.post(
        url(pid, "/treatment-orders"),
        json={"artifact_id": artifact["id"], "order_type": "wet_storage", "title": "湿存检查", "assignee_id": conservator["id"], "lease_minutes": 30},
        headers=owner["headers"],
    )
    assert order.status_code == 201
    order = order.json()
    assert order["status"] == "open"

    wrong_claim = client.post(url(pid, f"/treatment-orders/{order['id']}/claim"), headers=team["conservator2"]["headers"])
    assert wrong_claim.status_code == 403

    claimed = client.post(url(pid, f"/treatment-orders/{order['id']}/claim"), headers=team["conservator"]["headers"])
    assert claimed.status_code == 200
    claimed = claimed.json()
    assert claimed["status"] == "leased" and claimed["lease_until"]
    assert client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=owner["headers"]).json()["status"] == "in_treatment"

    transferred = client.post(
        url(pid, f"/treatment-orders/{order['id']}/transfer"),
        json={"assignee_id": conservator2["id"]},
        headers=team["conservator"]["headers"],
    )
    assert transferred.status_code == 200
    assert transferred.json()["status"] == "open" and transferred.json()["assignee_id"] == conservator2["id"]

    reclaimed = client.post(url(pid, f"/treatment-orders/{order['id']}/claim"), headers=team["conservator2"]["headers"])
    assert reclaimed.status_code == 200
    completed = client.post(url(pid, f"/treatment-orders/{order['id']}/complete"), json={"note": "已换水"}, headers=team["conservator2"]["headers"])
    assert completed.status_code == 200 and completed.json()["status"] == "done"
    assert client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=owner["headers"]).json()["status"] == "stored"

    actions = audit_actions(pid)
    for action in ("order.create", "order.claim", "order.transfer", "order.complete"):
        assert action in actions
    custody_types = [event["event_type"] for event in client.get(url(pid, f"/artifacts/{artifact['id']}/custody"), headers=owner["headers"]).json()["events"]]
    assert "treatment" in custody_types


def test_treatment_order_return_and_reassign(client, owner, project, team):
    pid = project["id"]
    artifact = register(client, team["recorder"]["headers"], pid, "LS-301")
    conservator = team["conservator"]["user"]
    conservator2 = team["conservator2"]["user"]
    order = client.post(
        url(pid, "/treatment-orders"),
        json={"artifact_id": artifact["id"], "order_type": "lab_handover", "title": "实验室交接", "assignee_id": conservator["id"]},
        headers=owner["headers"],
    ).json()
    client.post(url(pid, f"/treatment-orders/{order['id']}/claim"), headers=team["conservator"]["headers"])
    returned = client.post(url(pid, f"/treatment-orders/{order['id']}/return"), json={"reason": "缺少交接单据"}, headers=team["conservator"]["headers"])
    assert returned.status_code == 200
    assert returned.json()["status"] == "open" and returned.json()["assignee_id"] is None

    reassigned = client.post(url(pid, f"/treatment-orders/{order['id']}/transfer"), json={"assignee_id": conservator2["id"]}, headers=owner["headers"])
    assert reassigned.status_code == 200
    client.post(url(pid, f"/treatment-orders/{order['id']}/claim"), headers=team["conservator2"]["headers"])
    completed = client.post(url(pid, f"/treatment-orders/{order['id']}/complete"), json={}, headers=team["conservator2"]["headers"])
    assert completed.status_code == 200
    assert client.get(url(pid, f"/artifacts/{artifact['id']}"), headers=owner["headers"]).json()["status"] == "transferred"
    assert "order.return" in audit_actions(pid)


def test_lease_recovery_after_process_restart(client, owner, project, team):
    pid = project["id"]
    artifact = register(client, team["recorder"]["headers"], pid, "LS-302")
    conservator = team["conservator"]["user"]
    svc = ConservationService()
    order = svc.create_order(pid, {"id": owner["user"]["id"]}, {
        "artifact_id": artifact["id"],
        "order_type": "packaging",
        "title": "重新包装",
        "assignee_id": conservator["id"],
        "lease_minutes": 30,
    })
    claimed = svc.claim_order(pid, {"id": conservator["id"]}, order["id"], at="2026-09-20T08:00:00+00:00")
    assert claimed["status"] == "leased"

    close_connection()  # 模拟进程重启

    svc2 = ConservationService()
    recovered = svc2.recover_expired_leases(at="2026-09-20T08:31:00+00:00")
    assert recovered == 1
    orders = svc2.list_orders(pid, {"id": owner["user"]["id"]})["data"]
    assert orders[0]["status"] == "open"
    assert "order.lease_expired" in audit_actions(pid)

    reclaimed = svc2.claim_order(pid, {"id": conservator["id"]}, order["id"], at="2026-09-20T08:32:00+00:00")
    assert reclaimed["status"] == "leased"

    with pytest.raises(Exception) as excinfo:
        svc2.complete_order(pid, {"id": conservator["id"]}, order["id"], {}, at="2026-09-20T09:30:00+00:00")
    assert getattr(excinfo.value, "code", "") == "order_not_owned"


# ---- 重放与待办 ----
def test_replay_is_deterministic_and_side_effect_free(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    import_batch(client, headers, pid, "b1", [
        temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00"),
        temp_reading("TANK-1", 9.0, "2026-09-20T11:00:00+00:00"),
    ])
    payload = {"as_of": "2026-09-20T12:30:00+00:00", "readings": [temp_reading("TANK-1", 9.1, "2026-09-20T12:00:00+00:00")]}
    before_alerts = len(alert_rows(pid))
    before_batches = connection().execute("SELECT COUNT(*) FROM sensor_batches WHERE project_id=?", (pid,)).fetchone()[0]

    first = client.post(url(pid, "/replay"), json=payload, headers=owner["headers"])
    assert first.status_code == 200
    second = client.post(url(pid, "/replay"), json=payload, headers=owner["headers"])
    assert first.json() == second.json()

    replayed = first.json()
    assert len(replayed["alerts"]) == 1
    alert = replayed["alerts"][0]
    assert alert["status"] == "open" and alert["severity"] == "critical"
    assert alert["first_seen_at"] == "2026-09-20T10:00:00+00:00"
    assert replayed["todos"]["alerts"]["open"] == 1
    assert replayed["todos"]["alerts"]["by_severity"] == {"critical": 1}

    assert len(alert_rows(pid)) == before_alerts
    assert connection().execute("SELECT COUNT(*) FROM sensor_batches WHERE project_id=?", (pid,)).fetchone()[0] == before_batches

    forbidden = client.post(url(pid, "/replay"), json=payload, headers=team["viewer"]["headers"])
    assert forbidden.status_code == 403


def test_todo_summary_reflects_alerts_and_leases(client, owner, project, team):
    pid = project["id"]
    make_container(client, owner, pid)
    publish_scheme(client, owner, pid)
    headers = team["recorder"]["headers"]
    import_batch(client, headers, pid, "b1", [temp_reading("TANK-1", 9.5, "2026-09-20T10:00:00+00:00")])
    artifact = register(client, headers, pid, "LS-400", "TANK-1")
    conservator = team["conservator"]["user"]
    svc = ConservationService()
    order = svc.create_order(pid, {"id": owner["user"]["id"]}, {
        "artifact_id": artifact["id"],
        "order_type": "wet_storage",
        "title": "湿存巡检",
        "assignee_id": conservator["id"],
        "lease_minutes": 30,
    })
    svc.claim_order(pid, {"id": conservator["id"]}, order["id"], at="2026-09-20T10:00:00+00:00")

    todos = client.get(url(pid, "/todos"), params={"as_of": "2026-09-20T12:00:00+00:00"}, headers=owner["headers"])
    assert todos.status_code == 200
    summary = todos.json()
    assert summary["alerts"]["open"] == 1
    assert summary["alerts"]["items"][0]["duration_minutes"] == 120.0
    assert summary["orders"]["leased"] == 1
    assert summary["orders"]["lease_expired"] == 1
    assert summary["orders"]["items"][0]["lease_expired"] is True
