# xtunnel

> 本仓库是 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 的**自制 TypeScript 多文件重构版**：
> 与上游**行为等价**（中文配置键、订阅输出、认证公式 `MD5MD5(UA+KEY+ADMIN)`、品牌常量、KV 键名全部兼容），
> 代码组织改为模块化可插拔（Transport / Protocol / ChainProvider / Plugin 四大基类）。
> **部署方式与上游不同：必须 `wrangler deploy` 构建部署，不再支持控制台粘贴单文件。**
> 架构与迁移设计见 [DESIGN.md](./DESIGN.md)。

![后台页面](./img.png)

---

## 📖 项目简介

**xtunnel** 是一个基于 CF Workers/Pages 平台的边缘计算隧道解密方案。它能够高效地处理网络流量，并提供强大的管理面板和灵活的节点配置能力。

### ✨ 核心特性

- 🛡️ **协议支持**：支持 VLESS、Trojan、Shadowsocks 等主流协议，深度集成加密传输。
- 📊 **管理面板**：内置可视化后台，支持实时配置修改、日志查看及流量统计。
- 🔌 **可插拔架构**：传输层（WS / gRPC / xHTTP）、协议层、链式代理（SOCKS5 / HTTP / HTTPS / TURN / SSTP）与功能插件（订阅 / 优选 / 管理 API / 伪装页）均为对象化组件，按注册表扩展。
- 🔄 **订阅系统**：内置自动订阅生成及混淆转换，适配主流客户端（Clash, Sing-box, Surge 等）。
- ⚡ **性能加速**：支持自定义 ProxyIP、SOCKS5/HTTP 链式代理及优选 API，优化网络延迟。
- 🌐 **多台适配**：完美适配 Windows, Android, iOS, MacOS 及各种软路由固件。

---

## 🔀 与上游的差异

- **代码组织**：上游 `_worker.js` 单文件（约 6700 行）→ `src/` 下 TypeScript 多文件（strict 模式）。
- **页面本地化**：登录 / 管理 / noADMIN / noKV 页面由运行时 `fetch` 远程站点改为本地 Static Assets（`assets/pages/`，随 Worker 一起部署）；Google Fonts 外链已移除（系统字体栈），第三方 IP 查询 API 保留。
- **部署方式**：`wrangler.toml` 声明 `assets` 绑定且 `run_worker_first = true`（路由与认证先经 Worker），因此**必须** `wrangler deploy`；上游的「粘贴 `_worker.js`」「Pages 上传 zip」方式不再适用。
- **对照物归档**：上游单文件与其 25 个行为向量测试归档在 `archive/`（`_worker.js` + `test_rename.mjs`），迁移期用于逐行为对照，`node archive/test_rename.mjs` 可随时回归。

---

## 🚀 快速开始

### 环境要求

- Node.js 20+（本仓库开发验证于 Node 26）与 npm
- Cloudflare 账号

### 本地开发

```bash
npm install
npm run dev      # wrangler dev → http://127.0.0.1:8787
npm run check    # tsc --noEmit 类型检查
npm test         # vitest 全量单测
```

> 本地以 http 提供服务，而 Worker 的 http→https 301 会把非传输层请求重定向到 `https://127.0.0.1:8787`（本地无 TLS 监听）。
> 因此 `/login`、`/sub` 等 HTTP 路由需部署到线上域名后验证；WS / gRPC / xHTTP 传输与 `/version` 可直接本地测，
> HTTP 路由行为由 `test/` 单测覆盖。

### 部署（wrangler deploy）

1. 安装依赖：
   ```bash
   npm install
   ```
2. 绑定 KV：在 Cloudflare 控制台创建 KV 命名空间，绑定变量名必须为 **KV**；
   将命名空间 id 填入 `wrangler.toml` 的 `[[kv_namespaces]]`（取消该段注释）。
3. 配置管理密码 **ADMIN**：推荐部署后在 Workers 仪表盘「设置 → 变量」中添加
   （`keep_vars = true`，`wrangler deploy` 不会清除仪表盘已有变量）；
   也可写入 `wrangler.toml` 的 `[vars]`，但请勿把密码提交进仓库。
4. 构建部署：
   ```bash
   npx wrangler deploy
   ```
   wrangler 会打包 `src/index.ts` 并上传 `assets/` 静态页面。
5. 在控制台「触发器 → 添加自定义域」绑定你的域名，等待证书生效。
6. 访问 `https://你的域名/admin`，输入 ADMIN 密码即可登录后台。

---

## 🔑 环境变量说明

| 变量名 | 必填 | 示例 | 详细备注 |
| :--- | :---: | :--- | :--- |
| **ADMIN** | ✅ | `123456` | 后台管理面板登录密码 |
| **KEY** | ❌ | `CMLiussss` | 快速订阅路径密钥，访问 `/CMLiussss` 即可快速获取节点 |
| **UUID** | ❌ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | 强制固定UUID，只支持**UUIDv4**标准格式 |
| **PROXYIP** | ❌ | `proxyip.cmliussss.net:443` | 全局自定义反代 IP  |
| **URL** | ❌ | `https://cloudflare-error-page-3th.pages.dev` | 默认主页伪装地址（可填写网页 URL 或 `1101`） |
| **GO2SOCKS5** | ❌ | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | 强制走 SOCKS5 的名单 (`*` 为全局，域名用逗号分隔) |
| **DEBUG** | ❌ | `1`或`true` | **开发者模式**，默认**关闭**调试日志功能（console.log），设置`1`或`true`则**开启**调试日志功能 |
| **OFF_LOG** | ❌ | `1`或`true` | 默认**开启**KV日志记录功能，设置`1`或`true`则**关闭**日志记录功能 |
| **BEST_SUB** | ❌ | `1`或`true` | 默认**关闭**作为**优选订阅生成器**的功能，设置`1`或`true`则**开启**该功能 |
| **PRELOAD_RACE_DIAL** | ❌ | `1`或`true` | 默认**关闭**作为**预加载竞速拨号**的功能，设置`1`或`true`则**开启**该功能 |
| **TCP_CONCURRENT_DIAL**   | ❌ | `2` | **TCP 并发拨号数**，默认值为`2`；设置后不再根据中国移动网络自动降为单路 |
| **PROXY_CONCURRENT_DIAL** | ❌ | `1` | **反代并发拨号数**，默认值为`1`；数值越高连接速度越快，但 IP 切换也越频繁 |

---

## 🔧 高级实用技巧
如需修改 **订阅地址里的TOKEN** 和 **用于节点验证的UUID** ，可通过修改变量
1. 修改`ADMIN`或`KEY`变量的值，可以随机修改 **订阅地址里的TOKEN** 和 **用于节点验证的UUID**
2. 设置`UUID`变量可以强制固定 **订阅地址里的TOKEN** 和 **用于节点验证的UUID**，注意必须是**UUIDv4**标准格式，否则会导致节点无法使用。

本工具支持通过 **PATH路径** 动态切换底层代理方案：

- 指定 `PROXYIP` 案例
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   ```

- 指定 `SOCKS5` 案例
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (默认激活全局SOCKS5)
   /socks5://user:password@127.0.0.1:1080 (默认激活全局SOCKS5)
   ```

- 指定 `HTTP代理` 案例
   ```url
   /http=user:password@127.0.0.1:1080
   /http://user:password@127.0.0.1:8080 (默认激活全局SOCKS5)
   ```

- 指定 `Trojan fallback` 案例（由于使用场景为自建对接, 仅 Trojan 入站，fallback 服务需为同密码、非 WebSocket、非 TLS. 此时 UDP 透传给 fallback, 性能优秀, 功能完整）
   ```url
   /trojan=1.1.1.1:1234
   ```

---

## 💻 客户端适配情况

| 平台 | 推荐客户端 |
| :--- | :--- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **Android** | [v2rayNG](https://github.com/2dust/v2rayNG/releases)、[ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid/releases/)、[FlClash](https://github.com/chen08209/FlClash/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **iOS** | Surge、Shadowrocket、Stash、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、Loon、Egern、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、Quantumult X |
| **macOS** | [FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、Surge、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、[FlyClash](https://github.com/GtxFury/FlyClash/releases) |
| **鸿蒙** | [ClashBox](https://github.com/xiaobaigroup/ClashBox/releases) |

---

## 📁 项目结构

```
src/
  index.ts          # Worker 入口（HTTP 路由 → 传输 → 会话编排）
  router.ts         # HTTP 路由分发（核心路由 + 插件链 + 伪装页兜底）
  context.ts        # 每请求上下文（env / userId / identity / 调优参数）
  config/           # 配置 schema、加载器、中文键双向迁移（85 对）
  protocol/         # VLESS / Trojan / Shadowsocks 解析与加解密
  transport/        # WebSocket / gRPC / xHTTP 传输
  forward/          # 转发核心（并发拨号、Grain 合包、上下行泵、DoH 解析）
  chain/            # 链式代理五件套 + 自研 TLS（tls/）
  plugins/          # Subscription / BestIp / AdminUi / FakePage 四插件
  session/          # 会话编排（首包 → 协议 → 转发）
  services/ auth.ts # 品牌常量、MD5、日志、CF 用量、DoH、认证
  utils/            # 字节 / 数组 / 掩码 / 网络 纯函数
assets/pages/       # 登录 / 管理 / noADMIN / noKV 页面（Static Assets）
test/               # vitest 单测（261 用例）
archive/            # 上游单文件对照物（_worker.js + test_rename.mjs，25 向量）
DESIGN.md           # 架构设计与 P0–P8 迁移方案
```

---

## 🧪 开发与测试

- `npm run check`：TypeScript strict 类型检查。
- `npm test`：vitest 全量单测（协议向量、配置键迁移、认证、传输、转发、链式、插件路由）。
- `node archive/test_rename.mjs`：对上游 `_worker.js` 跑 25 个行为向量（迁移期对照基准）。
- 各阶段验收标准与兼容红线见 [DESIGN.md](./DESIGN.md) 第 10、11 章。

---

## ⭐ 项目热度

![Stargazers over time](https://github.com/cmliu/cmliu/blob/main/star/edgetunnel.svg)

---

## 🙏 特别鸣谢
### 💖 赞助支持 - 提供云服务器维持[订阅转换服务](https://sub.cmliussss.net/)
- [Yuusei Network](https://yuusei.io/)
- [VMRack](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)

### 🛠 开源代码引用
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) —— 上游项目（本仓库的行为基准）
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [股神](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [白嫖哥](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [ToiCF/CF-Workers-HTTPS](https://github.com/ToiCF/CF-Workers-HTTPS)
- [ToiCF/CF-Workers-TURN](https://github.com/ToiCF/CF-Workers-TURN)
- [ToiCF/CF-Workers-SoftEther](https://github.com/ToiCF/CF-Workers-SoftEther)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)
- [zhangtaile](https://github.com/cmliu/edgetunnel/pull/999)
- [1345695](https://github.com/1345695/edcloudwasm)
- [ToiCF/GrainTCP](https://github.com/ToiCF/GrainTCP)
- [xream](https://github.com/cmliu/edgetunnel/pull/1359)

---

## ⚠️ 免责声明

1. 本项目（"xtunnel"）仅供**教育、科学研究及个人安全测试**之目的。
2. 使用者在下载或使用本项目代码时，必须严格遵守所在地区的法律法规。
3. 作者 **cmliu** 对任何滥用本项目代码导致的行为或后果均不承担任何责任。
4. 本项目不对因使用代码引起的任何直接或间接损害负责。
5. 建议在测试完成后 24 小时内删除本项目相关部署。
