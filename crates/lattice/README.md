# Lattice — HOLDFAST 知识库 Wiki

Lattice 是 HOLDFAST 主权基础设施中的**知识库 Wiki** 服务：服务端渲染的页面、Markdown 正文、
`[[wiki-链接]]`、以及每页一条简单的修订历史。它**自身不做任何登录**——坐落在 Sluice 网关
`auth=sso` 路由之后（子域 `wiki.w33d.xyz`），信任网关注入的身份头来标记编辑者。

- **语言/框架**：Rust + axum 0.8
- **子域**：`wiki.w33d.xyz`（网关 `auth=sso`）
- **内部端口**：`8720`
- **数据库**：`lattice`（每服务独立库）
- **设计**：HOLDFAST 企业级 UI（深色品牌渐变 + 靛蓝强调色），CSS 经 `include_str!` 内嵌，无静态资源往返

---

## 网关 SSO 模型（不要自建鉴权）

Lattice 是**仅内网**服务，只能经 Sluice 访问。网关完成 OIDC 浏览器登录后：

- **剥离**任何入站 `X-Auth-*`，再**注入**校验过的：
  - `X-Auth-Subject`：用户稳定 `sub`
  - `X-Auth-Email`：用户邮箱（顶栏「signed in as」+ 每次保存的编辑者/作者）
  - `X-Auth-Scope`：授权 scope
- 因此 Lattice **信任**这些头即为已认证用户，作者/编辑者**永不**取自客户端字段。
- 登出链接固定指向 `https://id.w33d.xyz/_gw/auth/logout`。

Sluice **不剥离路径前缀**：服务落在子域**根路径** `/`，上游收到**未改写**的完整路径，因此
路由就是字面量 `/`、`/w/{slug}`、`/edit/{slug}`、`/history/{slug}` 等，无需任何前缀配置。

---

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/healthz` | 存活探针 → `200 ok`（容器 HEALTHCHECK 用，公开） |
| GET | `/` | 页面索引（按标题排序，列出全部页面） |
| GET | `/new?title=…` | 便捷入口：把标题 slug 化后 303 跳转到编辑器 |
| GET | `/w/{slug}` | 渲染页面 Markdown；不存在则提示创建 |
| GET | `/edit/{slug}` | 编辑器（铸造 CSRF token，写 `__Host-lattice_csrf` cookie） |
| POST | `/edit/{slug}` | 保存：追加一条修订 + upsert 页面，303 跳回 `/w/{slug}` |
| GET | `/history/{slug}` | 修订历史列表（最新在前） |
| GET | `/coherence` | 维护视图：陈旧页面（超 `LATTICE_STALE_DAYS` 天未编辑）+ 矛盾候选（标题/术语高度重叠但正文分歧的启发式标记） |

未匹配路由渲染 HOLDFAST 风格的 404 页。

页面视图（`/w/{slug}`）底部追加 **Linked from / Related** 面板：显式反向链接（其他页面通过 `[[链接]]`
或 `/w/` Markdown 链接引用本页）+ 关键词重叠的相关页面（本地 TF-IDF 余弦，无外部 LLM）。该面板与
`/coherence` 全部由当前页面集即时计算，无新增表、无迁移；既有页面 CRUD/渲染逐字节不变。

### slug 规范化

URL slug 与 `[[wiki-链接]]` 目标都经同一个 `slugify`（小写、Unicode 字母数字、连字符分隔）。
因此 `/w/Foo Bar`、`/w/foo-bar`、`[[Foo Bar]]` 全部解析到唯一页面 `foo-bar`。读路径
（`/w`、`/history`）在 slug 非规范时 303 跳转到规范 URL，使地址栏始终干净、每页仅一个 URL。

### `[[wiki-链接]]`

正文支持 `[[Page Name]]` 与 `[[slug|显示文本]]`，渲染为指向 `/w/<slug>` 的链接。目标页**不存在**
时链接带 `wikilink--new` 类（红链，邀请创建）。代码块/行内代码中的 `[[ ]]` **不会**被转换。

---

## 安全

- **Markdown 净化**：原始/行内 HTML 在 pulldown-cmark **事件层**被中和（重新发射为转义文本），
  `<script>` / `<img onerror>` 等只会显示为字面文本。唯一原样输出的 HTML 是我们自己合成、
  href 仅含字母数字与连字符的 `[[wiki-链接]]` `<a>`，无注入面。所有不可信文本统一 HTML 转义。
- **CSRF（double-submit）**：状态变更 POST 必须携带与 `__Host-lattice_csrf` cookie 一致的隐藏
  表单 token（常量时间比对）。`__Host-` 前缀保证 cookie 仅经 TLS、`Path=/`、无 `Domain` 回送。
- **身份可信源**：编辑者邮箱只来自网关 `X-Auth-Email`。

---

## 数据模型（库 `lattice`）

仅用**可移植标准 SQL**（`TEXT`/`BIGINT`，`PRIMARY KEY`/`NOT NULL`，`INSERT .. ON CONFLICT
.. DO UPDATE`，普通索引），无 JSONB/数组/SERIAL/扩展，故未来可不改一字跑在 FusionDB（pgwire）上。
启动时幂等 `CREATE TABLE IF NOT EXISTS` 迁移。

```sql
CREATE TABLE IF NOT EXISTS pages (
    slug             TEXT PRIMARY KEY,
    title            TEXT   NOT NULL,
    body_md          TEXT   NOT NULL,
    updated_by_email TEXT   NOT NULL,
    updated_at       BIGINT NOT NULL,
    created_at       BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS revisions (
    id           TEXT PRIMARY KEY,   -- 随机 hex
    slug         TEXT   NOT NULL,
    body_md      TEXT   NOT NULL,
    editor_email TEXT   NOT NULL,
    ts           BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revisions_slug_ts ON revisions (slug, ts);
CREATE INDEX IF NOT EXISTS idx_pages_title       ON pages (title);
```

一次保存 = 一个原子操作（`Store::save_page`）：**upsert** `pages` 行 + **追加** 一条不可变
`revisions` 行（Postgres 实现包在一个事务里；`created_at` 在 upsert 中保留）。

### 存储抽象

`Store` 是 `async-trait`，两种实现：

- `InMemoryStore`：默认，无数据库，供 dev 与单测使用。
- `PgStore`：原生 `await` sqlx（运行时 `sqlx::query`/`Row`，**无** `query!` 宏，**无**
  `block_in_place`/同步桥接），故构建**不需要**数据库，worker 线程永不被 DB 往返阻塞。

由 `LATTICE_STORE` 选择（`memory` 默认 / `postgres`）。

---

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:8720` | 监听地址 |
| `LATTICE_STORE` | `memory` | `memory` 或 `postgres` |
| `DATABASE_URL` | — | `LATTICE_STORE=postgres` 时必填，指向 `postgres:5432/lattice` |
| `LATTICE_STALE_DAYS` | `120` | `/coherence` 陈旧阈值：超过该天数未编辑的页面被标记为陈旧（可选，非负整数；非法值回落默认） |

---

## 构建 / 测试 / 运行

```bash
# 构建
cargo build

# Lint（零告警）
cargo clippy --all-targets -- -D warnings

# 默认测试套件（无数据库，内存 store）
cargo test

# Postgres 集成测试（需外部 PG；缺 TEST_DATABASE_URL 时自动跳过）
docker run --rm -d --name lattice-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=lattice \
  -p 127.0.0.1:55462:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55462/lattice \
  cargo test --test pg_store -- --nocapture
docker rm -f lattice-testpg

# 容器镜像
docker build -t holdfast/lattice:dev .

# 健康检查子命令（容器 HEALTHCHECK 用，无需 curl）
lattice healthcheck    # GET 127.0.0.1:$PORT/healthz，200 → exit 0
```

本地直跑（无网关时顶栏显示「— (no gateway session)」，编辑者回退为 `anonymous`）：

```bash
BIND_ADDR=127.0.0.1:8720 cargo run
# 浏览 http://127.0.0.1:8720/
```

---

## 部署要点

- **数据库**：`lattice`（部署步骤创建），`DATABASE_URL` 指向 `postgres:5432/lattice`，
  `LATTICE_STORE=postgres`。
- **内部端口**：`8720`（仅内网，不对外发布端口）。
- **路由**：`wiki.w33d.xyz` → `http://lattice:8720`，`auth=sso`。通配 `*.w33d.xyz` 已解析到本机，
  autocert 首次握手即签发 LE 证书，无需 DNS 动作。
- **Portal 磁贴**：名称 `Wiki`，描述「Knowledge base and runbooks.」，图标提示 `status`/通用网格
  （catalog 未知 icon 回退为网格图标），Beacon 组件名 `Wiki`。
- **Beacon 组件**：`Wiki`（http 探测 `http://lattice:8720/healthz`）。
