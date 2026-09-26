# 专利与技术秘密档案管理服务

这是一个面向研发机构、法务部门和保密办公室的模块化后端，集中管理专利交底资料、技术秘密载体、移交批次、受控副本签发、查阅借阅、对外披露、归还、合规处置、载体盘点、版本与载体来源、密级库位、泄密事件、登录权限、审计以及可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 已有能力

- 身份与权限：支持引导管理员、登录、会话、用户、角色和细粒度权限。
- 批次与二维码：移交批次保存项目、数量和稳定二维码载荷。
- 档案登记：登记专利交底、工艺文档、源代码介质等资产，保存密级库位和生命周期状态。
- 受控副本签发：一次事务内扣减来源载体、创建副本、记录损耗和版本来源事件。
- 查阅借阅归还：保存查阅用途、到期时间、部分归还和最终归还状态。
- 对外披露登记：使用幂等键登记合作方、披露范围和载体消耗，防止重复请求二次扣减。
- 位置脱敏：普通权限只能看到受限库位的替代码，授权人员可查看精确位置。
- 双人审批：合规处置、敏感库位解密等高风险操作要求申请人与审批人分离，并累计不同审批人的决定。
- 密级策略与调整：按项目（研发试验/量产）、资产类型与专利公开状态计算建议密级；升级与降级执行不同复核条件，全部调整保留旧值、依据与操作者，普通管理员无法绕过复核直接改密级。
- 会话级临时解密：临时解密只对指定查阅借阅会话在限定时间窗内生效，到期自动失效，服务重启不会让过期授权复活。
- 泄密事件追踪：事件可以关联档案或移交批次，保存严重度、调查状态和处置结果。
- 审计与任务：关键身份及业务操作留痕，后台任务支持去重、领取与完成。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/archives.db`，可用 `ARCHIVE_DATABASE_PATH` 指定其他路径。

## 初始化与完整性检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 测试

```bash
python -m pytest
```

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

## 密级管理接口（`/api/secrecy`）

- `PUT /projects/profile`、`GET /projects/profile`：维护项目研发试验/量产阶段档案。
- `PUT /policy/rules`、`GET /policy/rules`：维护（项目、资产类型、阶段、公开状态）→建议密级的规则；未配置规则时使用内置基线。
- `POST /policy/suggest`：按项目、资产类型与公开状态计算建议密级及理由。
- `POST /dossiers/{id}/patent-publication`：登记专利公开日，此后禁止升级，降级须匹配策略建议值。
- `POST /adjustments` + `POST /adjustments/{id}/reviews`：发起与复核密级调整。升级需两名不同复核人且至少一人属保密办公室（72 小时内），降级需一名保密办公室复核人（120 小时内）；申请人不能复核自己的申请，逾期申请自动过期。
- `POST /temporary-declassifications`、`GET ...`、`POST .../{id}/revoke`：临时解密绑定具体查阅借阅会话，最长 7 天且不得晚于借阅到期，过期/撤销后自动恢复基础密级。
- `GET /dossiers/{id}/effective-level?access_loan_id=`：查询基础密级与指定会话内的生效密级。
- `GET /dossiers/{id}/history`：显示每次变更的生效时间、操作者、依据、旧值新值以及仍在使用临时解密的会话。

密级没有任何直接写入接口，管理员只能通过上述复核流程改变密级。

