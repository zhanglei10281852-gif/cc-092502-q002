# 考古研究协作基础服务

这是一个供考古项目扩展业务模块的纯后端基础服务，提供研究项目登记、成员与角色、会话认证、审计事件、幂等请求和可恢复后台任务。服务使用 FastAPI 与 SQLite，不依赖另行部署的数据库、缓存或队列。

## 环境与安装

运行环境为 Python 3.11。安装开发依赖：

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## 初始化与启动

```bash
python -m app.cli init-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

基础接口包括 `/api/system/health`、`/api/projects`、`/api/users`、`/api/sessions`、`/api/audit` 和 `/api/jobs`。首次启动后可用命令行创建管理员，也可以通过测试夹具构造隔离数据库。

## 测试

```bash
python -m pytest
```

测试覆盖数据库初始化、项目成员权限、会话撤销、审计脱敏、幂等写入和后台任务领取与完成。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

该命令在进程内检查根路径、健康接口、数据库外键和 WAL 配置。

## 扩展约定

新研究模块应通过独立路由、服务和仓储接入，跨表写入放在即时事务中。外部标识、幂等键和审计载荷应保存原始值及规范化值；后台任务使用 SQLite 租约，不允许依赖外部队列。用户口令和会话令牌只保存摘要，审计事件会过滤密码、令牌等敏感字段。

## 有机遗物保护处置模块

面向深埋饱水淤泥出土的木构件（wood）、编织物（textile）、绳索（rope）等有机遗物，覆盖登记、环境监测、告警、处置单与包装链路。路由统一挂在 `/api/projects/{project_id}/conservation` 下，表结构在应用启动时随基础库一并初始化。

### 角色

在基础角色上新增 `conservator`（保护人员）。登记员（recorder）负责遗物与容器登记；负责人（owner/researcher）发布阈值方案、创建与指派处置单；保护人员领取、转交、完成或退回处置单并确认告警；敏感库位仅 owner/researcher/conservator 可见，其余角色读取时被脱敏（`location_id` 置空并标记 `location_hidden`）。

### 登记与保管链路

- `POST /locations`、`POST /containers`：库位（可标记 `sensitive`）与容器（按遗物类别专用）。
- `POST /artifacts`：按临时编号登记材质判断、出土环境、容器与当前保管位置；临时编号在项目内唯一，重复返回 409。
- `POST /containers/{id}/merge`、`POST /containers/{id}/split`：合并或拆分包装，逐件遗物写入 `custody_events`，`GET /artifacts/{id}/custody` 可回放完整链路；类别不一致或遗物不在来源容器时整体回滚。

### 阈值方案与传感批次

- `POST /thresholds`：按类别发布新版本（旧版本同时退役），配置含各指标上下限、`missing_after_minutes` 与按持续时间升级的梯度（`escalation`），发布与变更均留审计。
- `POST /sensor-batches`：离线批次导入温度、湿度、浸泡液（pH、电导率）读数。`batch_key` 项目内唯一，重复批次返回首次导入的摘要且不产生副作用；单条读数按 `(container, metric, observed_at)` 去重；任一读数非法则整批回滚。

### 告警语义

- 越界读数形成"越界片段"，同一片段只产生一条告警（去重）；片段持续时间跨过升级梯度时级别单调上升（warning → elevated → critical），降级不发生。
- 片段由该容器该指标的全部历史读数重算，读数乱序到达、迟到读数切分或延伸片段时，告警状态都会收敛到同一确定结果（旧告警收回并留审计）。
- 缺测检测在首个读数之后启动：相邻读数间隔扣除维护窗口（可跨日）覆盖时间后超过 `missing_after_minutes` 才告警，维护窗口内的缺测不误报。
- `POST /evaluate` 以指定 `as_of` 全量重算（升级推进与缺测检测的周期入口）；`POST /replay` 用同一评估函数离线重放一批读数，只读无副作用，相同输入得到确定相同的告警与待办摘要；`GET /todos` 输出当前告警与处置单待办。

### 处置单租约

- 处置单类型：湿存（wet_storage）、包装（packaging）、转运（transport）、实验室交接（lab_handover）；一件遗物同时只允许一张进行中的处置单。
- 只有被指派的保护人员可领取（`claim`），领取获得带截止时间的租约；持有人或负责人可转交（`transfer`，重新指派保护人员）；只有租约持有人可完成（`complete`）或退回（`return`，须填原因并清空指派）。
- 租约状态持久化在 SQLite 中，超时租约在进程重启时由启动钩子统一恢复为可领取状态，领取/转交/完成/退回时也会惰性回收；所有状态转换、阈值变更与交接均写入审计事件。
