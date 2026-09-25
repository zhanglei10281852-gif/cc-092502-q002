"""有机遗物模块的表结构。

设计要点：
- 遗物的库位（location_code）对无权限角色脱敏，鉴权在服务层完成；
- 阈值方案按材质（material_kind）维护版本，永远新增版本而不是覆盖；
- 告警（alerts）按 (artifact_id, metric, violation_kind) 去重，
  连续越界只开一条，持续期间按持续时间升级；
- 维护窗口抑制缺测误报；
- 处置单（handling orders）使用持久化租约，lease_until 到期即可在
  进程重启后被其他保护人员重新领取；
- 包装（packages）与遗物多对多，合包/拆包通过包装关系变更记录
  保留每件遗物的完整链路（artifact_chain + package_changes）。
"""

from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS org_artifacts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 temp_number TEXT NOT NULL,
 material_kind TEXT NOT NULL CHECK(material_kind IN ('wood','textile','rope','other')),
 material_detail TEXT NOT NULL DEFAULT '',
 burial_env TEXT NOT NULL CHECK(burial_env IN ('saturated_silt','waterlogged','wet','damp','unknown')),
 storage_state TEXT NOT NULL CHECK(storage_state IN ('wet_kept','immersed','wrapped','drying','stable')),
 container_code TEXT NOT NULL DEFAULT '',
 immersion_fluid TEXT NOT NULL DEFAULT '',
 location_code TEXT NOT NULL DEFAULT '',
 notes TEXT NOT NULL DEFAULT '',
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(project_id,temp_number)
);
CREATE INDEX IF NOT EXISTS idx_org_artifacts_project ON org_artifacts(project_id);

CREATE TABLE IF NOT EXISTS org_threshold_schemes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 material_kind TEXT NOT NULL CHECK(material_kind IN ('wood','textile','rope','other')),
 version INTEGER NOT NULL,
 active INTEGER NOT NULL DEFAULT 1,
 rules_json TEXT NOT NULL,
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 UNIQUE(project_id,material_kind,version)
);
CREATE INDEX IF NOT EXISTS idx_org_threshold_active ON org_threshold_schemes(project_id,material_kind,active);

CREATE TABLE IF NOT EXISTS org_maintenance_windows (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 location_code TEXT NOT NULL DEFAULT '',
 metric TEXT NOT NULL DEFAULT '',
 start_at TEXT NOT NULL,
 end_at TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT '',
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_maint_lookup ON org_maintenance_windows(project_id,start_at,end_at);

CREATE TABLE IF NOT EXISTS org_sensor_batches (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 batch_ref TEXT NOT NULL,
 source TEXT NOT NULL DEFAULT '',
 payload_hash TEXT NOT NULL DEFAULT '',
 summary_json TEXT NOT NULL DEFAULT '{}',
 imported_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 received_at TEXT NOT NULL,
 reading_count INTEGER NOT NULL DEFAULT 0,
 UNIQUE(project_id,batch_ref)
);

CREATE TABLE IF NOT EXISTS org_sensor_readings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 batch_id INTEGER NOT NULL REFERENCES org_sensor_batches(id) ON DELETE CASCADE,
 artifact_id INTEGER REFERENCES org_artifacts(id) ON DELETE CASCADE,
 location_code TEXT NOT NULL DEFAULT '',
 metric TEXT NOT NULL CHECK(metric IN ('temperature','humidity','fluid_ph','fluid_ec','fluid_level','oxygen')),
 value REAL NOT NULL,
 measured_at TEXT NOT NULL,
 ingested_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_readings_dedup
 ON org_sensor_readings(COALESCE(artifact_id,-1),location_code,metric,measured_at);
CREATE INDEX IF NOT EXISTS idx_org_readings_scan
 ON org_sensor_readings(project_id,artifact_id,metric,measured_at);

CREATE TABLE IF NOT EXISTS org_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 artifact_id INTEGER NOT NULL REFERENCES org_artifacts(id) ON DELETE CASCADE,
 metric TEXT NOT NULL,
 violation_kind TEXT NOT NULL,
 dedup_key TEXT NOT NULL,
 level TEXT NOT NULL CHECK(level IN ('warning','serious','critical')),
 status TEXT NOT NULL CHECK(status IN ('open','escalated','resolved')),
 scheme_version INTEGER NOT NULL DEFAULT 0,
 first_reading_at TEXT NOT NULL,
 latest_reading_at TEXT NOT NULL,
 resolved_at TEXT NOT NULL DEFAULT '',
 escalations_json TEXT NOT NULL DEFAULT '[]',
 reading_ids_json TEXT NOT NULL DEFAULT '[]',
 todo_order_id INTEGER REFERENCES org_handling_orders(id) ON DELETE SET NULL,
 UNIQUE(project_id,dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_org_alerts_open ON org_alerts(project_id,status,artifact_id);

CREATE TABLE IF NOT EXISTS org_packages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 package_code TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL CHECK(status IN ('active','merged','split','dissolved')),
 parent_package_id INTEGER REFERENCES org_packages(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_package_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 package_id INTEGER NOT NULL REFERENCES org_packages(id) ON DELETE CASCADE,
 artifact_id INTEGER NOT NULL REFERENCES org_artifacts(id) ON DELETE CASCADE,
 added_at TEXT NOT NULL,
 removed_at TEXT NOT NULL DEFAULT '',
 change_id INTEGER REFERENCES org_package_changes(id) ON DELETE SET NULL,
 UNIQUE(package_id,artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_org_pkg_items_artifact ON org_package_items(artifact_id);

CREATE TABLE IF NOT EXISTS org_package_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 change_type TEXT NOT NULL CHECK(change_type IN ('create','merge','split','dissolve')),
 source_package_ids_json TEXT NOT NULL DEFAULT '[]',
 target_package_id INTEGER REFERENCES org_packages(id) ON DELETE SET NULL,
 artifact_ids_json TEXT NOT NULL DEFAULT '[]',
 actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_handling_orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 order_no TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('wet_storage','repack','transfer','lab_handover','inspection')),
 priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
 reason TEXT NOT NULL DEFAULT '',
 artifact_ids_json TEXT NOT NULL DEFAULT '[]',
 package_id INTEGER REFERENCES org_packages(id) ON DELETE SET NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','claimed','completed','returned','cancelled')),
 assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 alert_id INTEGER REFERENCES org_alerts(id) ON DELETE SET NULL,
 lease_until TEXT NOT NULL DEFAULT '',
 result_note TEXT NOT NULL DEFAULT '',
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(project_id,order_no)
);
CREATE INDEX IF NOT EXISTS idx_org_orders_status ON org_handling_orders(project_id,status,lease_until);

CREATE TABLE IF NOT EXISTS org_order_transitions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES org_handling_orders(id) ON DELETE CASCADE,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 from_status TEXT NOT NULL,
 to_status TEXT NOT NULL,
 actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_order_trans ON org_order_transitions(order_id,id);

CREATE TABLE IF NOT EXISTS org_artifact_chain (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 artifact_id INTEGER NOT NULL REFERENCES org_artifacts(id) ON DELETE CASCADE,
 event_type TEXT NOT NULL CHECK(event_type IN ('register','repackage','merge','split','transfer','lab_handover','return','location','note')),
 from_package_id INTEGER REFERENCES org_packages(id) ON DELETE SET NULL,
 to_package_id INTEGER REFERENCES org_packages(id) ON DELETE SET NULL,
 location_code TEXT NOT NULL DEFAULT '',
 ref_type TEXT NOT NULL DEFAULT '',
 ref_id TEXT NOT NULL DEFAULT '',
 actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 detail_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_chain_artifact ON org_artifact_chain(artifact_id,id);
"""
