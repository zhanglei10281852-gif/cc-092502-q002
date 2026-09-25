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

## 有机遗物保护处置模块

面向深埋饱水淤泥出土木构件、编织物、绳索等有机遗物，路由统一挂在 `/api/projects/{project_id}/...` 下（代码位于 `app/organics/`）：

- **登记与保管**：`POST/GET /artifacts`、`PATCH /artifacts/{temp_number}`、`GET /artifacts/{temp_number}/chain`，记录材质判断、出土环境、湿存方式、容器、浸泡液与当前库位；每件遗物维护完整链路（注册、库位变更、合包、拆包、转运、实验室交接、退回）。
- **版本化阈值**：`POST/GET /threshold-schemes` 按材质发布规则版本（温度、湿度、浸泡液 pH/EC/液位、含氧量），新版本生效时旧版本保留但停用，发布操作留审计。
- **离线传感批次**：`POST /sensor-batches` 以批次号幂等导入；乱序时间戳按实际测量时刻归位，重复读数按 `(遗物/库位,指标,时刻)` 去重，重放同批次返回确定性的告警与待办摘要；同名批次内容不同返回 409。
- **去重告警与升级**：同一遗物同一指标同一方向的连续越界只产生一条告警，按持续时间升级 warning → serious → critical，并自动为 serious/critical 生成去重处置待办；正常读数或乱序补点会收敛、拆分告警段。
- **维护窗口**：`POST /maintenance-windows` 支持按库位/指标限定并可跨日；被窗口完全覆盖的采集缺口不会产生缺测误报（部分覆盖仍报）。
- **包装合拆**：`/packages`、`/packages/merge`、`/packages/split` 在事务中移动在籍遗物，旧包装保留 `merged/split` 状态与父子关系，每件遗物链路完整可溯；拆分必须覆盖包装内全部遗物，否则整笔失败回滚。
- **处置单租约**：`/handling-orders` 的领取、转交、完成、退回仅限项目 `owner`/`conservator`；领取写入 30 分钟持久化租约，到期后在任意进程（含重启后）的下次访问时自动回收为 queued，全部状态转换写入 `org_order_transitions` 与审计。
- **库位脱敏**：仅 `owner`/`conservator`/`recorder` 可见真实 `location_code`，其余角色在遗物、告警、包装、链路接口中一律得到 `***`。


## 测试

```bash
python -m pytest
```

测试覆盖数据库初始化、项目成员权限、会话撤销、审计脱敏、幂等写入和后台任务领取与完成；有机遗物模块另覆盖乱序时间补点、重复批次重放、跨日维护窗口、越界去重升级、租约到期恢复与失败事务回滚（`tests/test_organics_*.py`）。

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
