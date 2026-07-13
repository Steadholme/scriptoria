# Lattice — HOLDFAST Knowledge Workspace

Lattice 是 HOLDFAST 主权基础设施中的**知识工作区**：它把服务端渲染的 Markdown 文档、层级结构、
`[[wiki-链接]]`、反向链接、修订历史与 coherence（知识一致性）信号放在同一个阅读和编辑上下文中。
它**自身不做任何登录**——坐落在 Sluice 网关 `auth=sso` 路由之后（子域 `wiki.w33d.xyz`），
信任网关注入的身份头来标记编辑者。

- **语言/框架**：Rust + axum 0.8
- **子域**：`wiki.w33d.xyz`（网关 `auth=sso`）
- **内部端口**：`8720`
- **数据库**：`lattice`（每服务独立库）
- **设计**：Odyssey token、主题与语言能力之上的 Lattice editorial workspace；CSS 经
  `include_str!` 内嵌，无外部静态资源往返

## Knowledge Workspace v1

- **Library**：首页同时呈现层级 Knowledge map、最近更新、全量目录、快速创建与 Coherence 入口；
  最近更新复用有界的结构查询，只渲染标题、更新时间与编辑者，不输出正文。
- **Document**：桌面端采用「Page tree / 中央文章 / Inspector」三栏阅读模型；Inspector 固定提供
  Outline、Backlinks、Related、History、文档元数据、结构调整及陈旧/孤立信号。窄屏按自然文档流折叠。
- **Edit**：Markdown source 与安全预览并排；初始预览使用服务端 sanitizer，输入后的渐进预览只通过
  DOM `textContent` 创建节点。无 JavaScript 时仍是普通 POST form，CSRF 与 `base_rev` 冲突保护不变。
- **Estate preferences**：每个请求读取 `__Secure-lang` 与 `__Secure-theme`，动态设置 `<html lang>`、
  `data-theme` 和 `color-scheme`，并复用 Odyssey 的无 JavaScript 切换器。

---

## 网关 SSO 模型（不要自建鉴权）

Lattice 的容器上游仅在内部网络暴露；用户通过公网域名进入 Sluice，完成 OIDC 浏览器登录后访问：

- **剥离**任何入站 `X-Auth-*`，再**注入**校验过的：
  - `X-Auth-Subject`：用户稳定 `sub`
  - `X-Auth-Email`：用户邮箱（顶栏「signed in as」+ 每次保存的编辑者/作者）
  - `X-Auth-Scope`：授权 scope
- 因此 Lattice **信任**这些头即为已认证用户，作者/编辑者**永不**取自客户端字段。
- 登出链接固定指向 `https://sso.w33d.xyz/_gw/auth/logout`。

Sluice **不剥离路径前缀**：服务落在子域**根路径** `/`，上游收到**未改写**的完整路径，因此
路由就是字面量 `/`、`/w/{slug}`、`/edit/{slug}`、`/history/{slug}` 等，无需任何前缀配置。

---

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/healthz` | 存活探针 → `200 ok`（容器 HEALTHCHECK 用，公开） |
| GET | `/` | Library：知识结构、最近更新、目录、创建与 Coherence 入口 |
| GET | `/recent` | 跨页面修订时间线（keyset pagination） |
| GET | `/new?title=…` | 便捷入口：把标题 slug 化后 303 跳转到编辑器 |
| GET | `/w/{slug}` | 中央文章 + Page tree + Inspector；不存在则提示创建 |
| GET | `/edit/{slug}` | split editor + 安全预览（铸造 CSRF token） |
| POST | `/edit/{slug}` | 保存：追加一条修订 + upsert 页面，303 跳回 `/w/{slug}` |
| GET | `/history/{slug}` | 修订历史列表（最新在前） |
| POST | `/revert/{slug}` | 把历史正文追加保存为新修订（不改写旧历史） |
| POST | `/move/{slug}` | 调整父页面；拒绝循环层级 |
| GET | `/coherence` | 维护视图：陈旧页面（超 `LATTICE_STALE_DAYS` 天未编辑）+ 矛盾候选（标题/术语高度重叠但正文分歧的启发式标记） |

未匹配路由渲染 HOLDFAST 风格的 404 页。

页面视图（`/w/{slug}`）在 Inspector 中持续展示 **Linked from / Related**：显式反向链接（其他页面
通过 `[[链接]]` 或 `/w/` Markdown 链接引用本页）+ 关键词重叠的相关页面（本地 TF-IDF 余弦，
无外部 LLM）。空关系也会明确显示为 `None yet`，使孤立文档成为可见的维护信号。

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
- **编辑预览**：服务端初始预览走同一 Markdown sanitizer；浏览器渐进预览只写 `textContent`，
  不把草稿分配给 `innerHTML`。预览不参与保存授权，关闭 JavaScript 后安全语义不变。
- **冲突保护**：编辑 form 携带打开页面时的 `base_rev`；当前 head 已变化时返回 `409` 并同时保留
  双方文本，不产生页面写入或 audit event。

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

ALTER TABLE pages ADD COLUMN IF NOT EXISTS parent_id TEXT;

CREATE TABLE IF NOT EXISTS revisions (
    id           TEXT PRIMARY KEY,   -- 随机 hex
    slug         TEXT   NOT NULL,
    body_md      TEXT   NOT NULL,
    editor_email TEXT   NOT NULL,
    ts           BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS page_links (
    from_slug TEXT NOT NULL,
    to_slug   TEXT NOT NULL,
    PRIMARY KEY (from_slug, to_slug)
);

CREATE INDEX IF NOT EXISTS idx_revisions_slug_ts ON revisions (slug, ts);
CREATE INDEX IF NOT EXISTS idx_revisions_ts_id ON revisions (ts, id);
CREATE INDEX IF NOT EXISTS idx_page_links_to_from ON page_links (to_slug, from_slug);
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
