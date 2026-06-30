# Pastefire

> HOLDFAST 主权基础设施中的企业级 **代码片段 / 粘贴板（pastebin）** 服务。

Pastefire 让登录用户快速分享代码片段：新建粘贴、按语言标注、设置过期时间、生成短链接（`/p/{id}`），
并提供 `text/plain` 原始视图（`/raw/{id}`）。它部署在 `paste.w33d.xyz` 子域，**只**通过网关 Sluice
对外暴露，由网关完成单点登录（SSO）。

## 设计要点（遵循 HOLDFAST 共享服务模板）

- **Rust + axum**，服务端渲染的企业级界面（HOLDFAST 设计语言，CSS 经 `include_str!` 内联，无静态资源往返）。
- **不做自己的登录**：位于 Sluice `auth=sso` 路由之后。网关执行 OIDC 浏览器登录，剥离入站的 `X-Auth-*`，
  再注入受信任的 `X-Auth-Subject` / `X-Auth-Email`。Pastefire 属于内网服务，因此**信任**这些头部作为
  已认证作者。粘贴的作者**永远**取自 `X-Auth-*`，绝不采信客户端字段。退出登录指向
  `https://id.w33d.xyz/_gw/auth/logout`。
- **异步 Postgres 存储**：`async-trait` 的 `Store` 抽象，提供内存实现（用于免数据库的测试）与
  `PgStore`（原生 `await` sqlx，**运行时查询**，无 `query!` 宏、无 `block_in_place`、无 sync-over-async）。
  仅使用**可移植标准 SQL**（`TEXT`/`BIGINT`、`PRIMARY KEY`/`NOT NULL`、`INSERT .. ON CONFLICT`、普通索引），
  以便日后在 FusionDB（pgwire）上原样运行。服务使用独立数据库 `pastefire`，启动时幂等执行
  `CREATE TABLE IF NOT EXISTS`。
- **安全**：所有生产者文本在渲染时进行 HTML 转义（防存储型 XSS）；原始视图以
  `text/plain; charset=utf-8` + `X-Content-Type-Options: nosniff` 返回，粘贴内容无法当作 HTML 执行；
  状态变更类 POST（创建、删除）采用双提交（double-submit）CSRF 校验。

## 数据模型（数据库 `pastefire`）

```text
pastes(
  id           TEXT PRIMARY KEY,   -- 短随机串，即 /p/{id} 短链
  title        TEXT NOT NULL,      -- 可为空字符串（渲染为 “Untitled paste”）
  body         TEXT NOT NULL,
  language     TEXT NOT NULL,      -- 语言标记（rust / plaintext / ...）
  author_sub   TEXT NOT NULL,      -- X-Auth-Subject（删除时的归属键）
  author_email TEXT NOT NULL,      -- X-Auth-Email（仅展示）
  created_at   BIGINT NOT NULL,    -- epoch 秒
  expires_at   BIGINT              -- 可空；NULL = 永不过期
)
```

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/healthz` | 存活探针（公开），容器 HEALTHCHECK 使用 |
| GET  | `/` | 新建粘贴表单（标题 + 语言 + 过期下拉 + 文本域）+「我最近的粘贴」|
| POST | `/` | 创建粘贴（CSRF 校验）→ `302` 跳转 `/p/{id}` |
| GET  | `/p/{id}` | 查看：等宽 `<pre>` + 语言标签 + 复制按钮 + `/raw/{id}` 链接；过期则 404 |
| GET  | `/raw/{id}` | 原始正文，`text/plain`；过期则 404 |
| POST | `/delete/{id}` | 删除本人粘贴（CSRF + 归属校验）→ `302` 跳转 `/` |

服务在子域**根路径**提供（Sluice 原样转发路径，不要假设有路径前缀）。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:8730` | 监听地址（内网端口 8730）|
| `PASTEFIRE_STORE` | `memory` | `memory`（免数据库）或 `postgres` |
| `DATABASE_URL` | — | `PASTEFIRE_STORE=postgres` 时必填，指向 `postgres:5432/pastefire` |

## 构建与测试

```bash
# 默认（免数据库）测试套件 + lint
cargo test
cargo clippy --all-targets -- -D warnings

# Postgres 集成测试（一次性数据库，端口 127.0.0.1:55463）
docker run --rm -d --name pf-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=pastefire \
  -p 127.0.0.1:55463:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55463/pastefire \
  cargo test --test pg_store -- --nocapture
docker rm -f pf-testpg

# 容器镜像
docker build -t holdfast/pastefire:dev .
docker run --rm -p 127.0.0.1:8730:8730 holdfast/pastefire:dev
curl -fsS http://127.0.0.1:8730/healthz   # -> ok
```

## 部署

- 数据库：`pastefire`（独立库，由部署创建）。
- 内网端口：`8730`。
- 网关路由：`paste.w33d.xyz`，`auth=sso`。
- Beacon 组件名：`Pastefire`。
- Portal 磁贴：名称 `Pastefire`，描述「Share code snippets and pastes across the estate.」，图标提示 `paste`/`code`。
