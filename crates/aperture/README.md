# Aperture — 图床 / 截图托管 + 文件网盘

Aperture 是 HOLDFAST 主权基础设施中的 **图片/截图托管 + 文件网盘** 服务，落子域
`drive.w33d.xyz`。Portal 磁贴名 **Drive**，Beacon 组件名 **Drive**。

- **栈**：Rust + axum，服务端渲染 HTML（内联 CSS，零静态资源往返）。
- **存储**：文件**字节**存入 [Cairn](../cairn)（S3 兼容对象存储，`http://cairn:9000`，bucket
  `aperture`）；文件**元数据**存入服务独占的 Postgres 数据库 `aperture`。
- **身份**：服务**自身不做登录**。它位于 Sluice `auth=sso` 路由之后，网关完成对 Keystone 的
  OIDC 浏览器登录，剥离入站 `X-Auth-*` 并注入可信的 `X-Auth-Subject` / `X-Auth-Email`。
  Aperture 仅内网可达，因此**信任**这两个头作为文件 owner。**唯一**的公开入口是分享路由
  `/s/{token}`（部署把 `/s/` 前缀标记为 `auth=public`），该路由从不读取身份。

## 端点

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET  | `/healthz` | public | 存活探针（容器 HEALTHCHECK 使用） |
| GET  | `/` | sso | 当前用户的网盘：上传拖拽区 + 文件网格（缩略图/图标、名称、大小、日期） |
| POST | `/upload` | sso | multipart 上传：字节入 Cairn，元数据落库 → 302 `/f/{id}`（CSRF） |
| GET  | `/f/{id}` | sso | 文件详情/预览页（图片内联预览，否则下载提示）。**仅 owner** |
| GET  | `/f/{id}/raw` | sso | 从 Cairn 串流字节（图片 `inline`，否则 `attachment`）。**仅 owner** |
| POST | `/delete/{id}` | sso | 删除自己的文件（元数据 + blob）→ 302 `/`（CSRF） |
| GET  | `/s/{token}` | **public** | 凭不可猜测 token 公开取文件，**无需 SSO** |

所有 SSO 路由强制**按用户归属**：非 owner 访问 `/f/{id}`、`/f/{id}/raw`、`/delete/{id}` 返回
403。跨用户访问只能通过分享 token。

## 数据模型（库 `aperture`，表 `files`）

```
files(
  id          TEXT PRIMARY KEY,     -- 短随机 URL-safe id（/f/{id} slug）
  owner_sub   TEXT NOT NULL,        -- X-Auth-Subject（归属键）
  name        TEXT NOT NULL,        -- 原始文件名（展示用，渲染转义）
  content_type TEXT NOT NULL,       -- 解析后的类型（图片走 magic 嗅探，否则净化客户端类型）
  size        BIGINT NOT NULL,      -- 字节数
  bucket      TEXT NOT NULL,        -- 对象存储 bucket
  object_key  TEXT NOT NULL,        -- 对象存储 key
  share_token TEXT NOT NULL UNIQUE, -- 不可猜测公开分享 token
  created_at  BIGINT NOT NULL       -- 上传时间（epoch 秒）
)
```

仅用可移植标准 SQL（TEXT/BIGINT，PK/UNIQUE/NOT NULL，参数化查询，`INSERT .. ON CONFLICT`，普通
索引），运行时查询（**无编译期宏**），因此构建**不需要数据库**，同样语句日后可在 FusionDB 经
pgwire 原样运行。

## 安全要点

- **CSRF**：所有状态变更 POST（上传、删除）走双提交 token（`__Host-csrf` cookie + 表单字段，
  常量时间比较）。
- **内容嗅探与防 XSS**：内联图片仅依据 **magic bytes** 判定（PNG/JPEG/GIF/WEBP/BMP）；其余一律
  以 `application/octet-stream` + `Content-Disposition: attachment` + `X-Content-Type-Options:
  nosniff` 下载，杜绝上传内容（含 `image/svg+xml`、HTML、脚本）在 `drive.w33d.xyz` 源内执行。
- **归属**：owner 永远取自网关注入头，绝不取自客户端字段。
- **大小限制**：`MAX_UPLOAD`（默认 25 MiB）+ axum body 上限。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:8900` | 监听地址 |
| `APERTURE_STORE` | `memory` | 元数据存储：`memory` \| `postgres` |
| `DATABASE_URL` | — | `postgres` 模式必填，指向 `postgres:5432/aperture` |
| `APERTURE_BLOBS` | `memory` | 对象存储：`memory` \| `s3` |
| `S3_ENDPOINT` | `http://cairn:9000` | Cairn 端点 |
| `S3_BUCKET` | `aperture` | bucket 名 |
| `S3_REGION` | `us-east-1` | 区域（Cairn 忽略，签名需要） |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | — | `s3` 模式必填 |
| `MAX_UPLOAD` | `26214400` | 单文件上限（字节，25 MiB） |
| `PUBLIC_BASE_URL` | `https://drive.w33d.xyz` | 渲染分享链接的公开基址 |

对象存储抽象为 `Blobs` trait：`MemoryBlobs`（进程内，dev/测试用）+ `S3Blobs`（Cairn，经
`object_store` 自定义端点 + path-style + allow-http）。元数据抽象为 `Store` trait：`InMemoryStore`
+ `PgStore`。两条 seam 都让默认测试套件**无需数据库、无需 Cairn**。

## 测试

```bash
# 默认套件：单元 + 端到端（内存元数据 + 内存对象存储，无外部依赖）
cargo test

# clippy 零告警
cargo clippy --all-targets -- -D warnings

# Postgres 集成（需外部 throwaway Postgres）
docker run --rm -d --name ap-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=aperture \
  -p 127.0.0.1:55490:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/aperture \
  cargo test --test pg_store -- --nocapture
docker rm -f ap-testpg
```

跨服务（真实 Cairn）联通在部署时校验。

## 构建镜像

```bash
docker build -t holdfast/aperture:dev .
```

多阶段、非 root（uid 10001）、仅 glibc（无 OpenSSL）。HEALTHCHECK 走内建
`aperture healthcheck` 子命令（裸 TCP 探 `/healthz`，无需 curl）。

## 部署接线（deploy/）

- compose 服务 `aperture`：`APERTURE_STORE=postgres`、`APERTURE_BLOBS=s3`、
  `DATABASE_URL=${APERTURE_DATABASE_URL}`、`S3_*` 指向 Cairn，仅内网（`http://aperture:8900`）。
- Sluice 路由（host `drive.w33d.xyz`）：`/s/` 前缀 `auth=public`，`/` 根 `auth=sso`。
- 依赖：Postgres（库 `aperture`）+ Cairn（bucket `aperture`）。
