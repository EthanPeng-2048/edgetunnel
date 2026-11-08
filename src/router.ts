/**
 * HTTP 路由分发（DESIGN.md §5「HTTP 链路」；对应原 _worker.js L102-550 的 else 分支）。
 *
 * 结构：version → 传输分发 → http→https → noADMIN → KV 门禁
 *   → **主路由插件链**（fast-sub/sub/locations/admin 子 API 认领；顺序与原
 *     else-if 链等价：fast-sub 先于 login，见 plugins/setup.ts）
 *   → 核心路由（login / admin 页与 config API / logout / robots.txt）
 *   → **兜底插件链**（FakePagePlugin：原 L526+ nginx/1101/反代伪装页）。
 * 认证集中走 auth.ts（cookie = MD5MD5(UA+KEY+ADMIN)，恒定时间比较）。
 */
import './plugins/setup';
import type { RequestContext } from './context';
import { UUID_REGEX } from './context';
import { computeAuthCookie, verifyAuthCookie, verifyPassword } from './auth';
import { loadConfig } from './config/loader';
import { migrateConfigKeysDeep, toLegacyConfig, CONFIG_KEY_CN_TO_EN } from './config/key-migration';
import { writeRequestLog } from './services/request-log';
import { selectTransport } from './transport/registry';
import { buildProxyContext } from './forward/proxy-ctx';
import { runSession } from './session/orchestrator';
import { getRoutePlugins, getFallbackPlugins } from './plugins/registry';
import { EDT_VERSION } from './services/brand';
import type { Config } from './config/schema';

const JSON_UTF8 = 'application/json;charset=utf-8';

function redirect(location: string, status = 302): Response {
  // 原 L114/L131/L322 的统一重定向体
  return new Response('重定向中...', { status, headers: { 'Location': location } });
}

function jsonResponse(data: unknown, status: number, pretty: boolean, contentType: string = JSON_UTF8): Response {
  return new Response(pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data), {
    status,
    headers: { 'Content-Type': contentType },
  });
}

/** 从 ASSETS 读取页面；ASSETS 未绑定或资源缺失返回 null */
async function loadAsset(rctx: RequestContext, assetPath: string): Promise<Response | null> {
  const assets = rctx.env.ASSETS;
  if (!assets) return null;
  const asset = await assets.fetch(new Request(new URL(assetPath, rctx.url.origin)));
  return asset.ok ? asset : null;
}

/** 错误兜底页（原 L104 noADMIN / L523 noKV）：404 + 禁缓存头，头集合继承资源响应 */
async function serveErrorPage(rctx: RequestContext, assetPath: string): Promise<Response> {
  const asset = await loadAsset(rctx, assetPath);
  if (!asset) return new Response('页面资源不存在', { status: 500 });
  const headers = new Headers(asset.headers);
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  headers.set('Pragma', 'no-cache');
  headers.set('Expires', '0');
  return new Response(asset.body, { status: 404, statusText: asset.statusText, headers });
}

/** 普通页面（原 L126 login / L320 admin，远程 200 直通语义） */
async function servePage(rctx: RequestContext, assetPath: string): Promise<Response> {
  const asset = await loadAsset(rctx, assetPath);
  if (!asset) return new Response('页面资源不存在', { status: 500 });
  return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers: asset.headers });
}

/** L111-126：登录页 GET/POST */
async function handleLogin(rctx: RequestContext): Promise<Response> {
  const adminPassword = rctx.adminPassword!;
  // L114 已登录 → /admin（原用 ==，此处恒定时间比较结果一致）
  if (await verifyAuthCookie(rctx.request, rctx.encryptionSecret, adminPassword)) {
    return redirect('/admin');
  }
  if (rctx.request.method === 'POST') {
    const formData = await rctx.request.text();
    const inputPassword = new URLSearchParams(formData).get('password');
    if (verifyPassword(inputPassword, adminPassword)) {
      // L118-124：密码正确 → JSON + Set-Cookie
      const response = jsonResponse({ success: true }, 200, false);
      const cookie = await computeAuthCookie(rctx.ua, rctx.encryptionSecret, adminPassword);
      response.headers.set('Set-Cookie', `auth=${cookie}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
      return response;
    }
    // 密码错误：原实现落回登录页（无错误提示）
  }
  return servePage(rctx, '/pages/login.html');
}

/** L321-324：登出（含访问 /<uuid> 清 cookie） */
function handleLogout(): Response {
  const response = redirect('/login');
  response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
  return response;
}

/**
 * L127-320：admin 分支核心部分（cookie 门禁 + config.json API + init + 管理页兜底）。
 * 注：log.json / getCloudflareUsage / getADDAPI / check（原 L228 loadConfig 之前短路）
 *     与 cf.json / tg.json / ADD.txt 已由 AdminUiPlugin / BestIpPlugin 在
 *     主路由链认领（本函数之前执行），语义与原 else-if 链顺序一致。
 */
async function handleAdmin(rctx: RequestContext): Promise<Response> {
  const { request, url, env } = rctx;
  const requestPath = url.pathname.slice(1).toLowerCase();
  const adminPassword = rctx.adminPassword!;

  // L131 cookie 门禁 → /login
  if (!(await verifyAuthCookie(request, rctx.encryptionSecret, adminPassword))) {
    return redirect('/login');
  }

  // L228：进入具体分发前统一加载配置（副作用：缺省初始化写 KV、TG/CF 默认文件）
  const config = await loadConfig(rctx);

  // L230-239：重置配置（任意方法，优先于 POST 分支 —— 与原 else-if 链一致）
  if (requestPath === 'admin/init') {
    try {
      const resetConfig = await loadConfig(rctx, { reset: true });
      rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Init_Config', resetConfig));
      resetConfig.init = '配置已重置为默认值';
      return jsonResponse(toLegacyConfig(resetConfig), 200, true);
    } catch (err) {
      const error = err as Error;
      return jsonResponse({ msg: `配置重置失败，失败原因：${error.message}`, error: error.message }, 500, true);
    }
  }

  // L240-308：POST 分支
  if (request.method === 'POST') {
    if (requestPath === 'admin/config.json') {
      try {
        const newConfig = (await request.json()) as Config;
        migrateConfigKeysDeep(newConfig, CONFIG_KEY_CN_TO_EN);
        // L246：完整性校验（中文键迁移后按英文键检查）
        if (!newConfig.UUID || !newConfig.HOST) return jsonResponse({ error: '配置不完整' }, 400, false);
        await env.KV!.put('config.json', JSON.stringify(newConfig, null, 2));
        rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Save_Config', config));
        return jsonResponse({ success: true, message: '配置已保存' }, 200, false);
      } catch (error) {
        console.error('保存配置失败:', error);
        return jsonResponse({ error: `保存配置失败: ${(error as Error).message}` }, 500, false);
      }
    }
    // cf.json / tg.json / ADD.txt 的 POST 已由 AdminUiPlugin 认领 —— 走到这里 = 未匹配
    return jsonResponse({ error: '不支持的POST请求路径' }, 404, false);
  }

  // L309-310：GET config.json —— 转回管理页中文键（Content-Type 无 charset，与原一致）
  if (requestPath === 'admin/config.json') {
    return jsonResponse(toLegacyConfig(config), 200, true, 'application/json');
  }

  // ADD.txt / cf.json 的 GET 已由 AdminUiPlugin 认领 —— 走到这里 = 未匹配子路径

  // L319-320：默认兜底 —— 记 Admin_Login 日志并返回管理页（GET /admin 及未匹配的 admin 子路径）
  rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Admin_Login', config));
  return servePage(rctx, `/pages/admin.html${url.search}`);
}

/** L76-88：version 版本信息接口（位于门禁之前，无需 adminPassword） */
function handleVersion(rctx: RequestContext): Response | null {
  const requestUuid = (rctx.url.searchParams.get('uuid') || '').toLowerCase();
  if (!UUID_REGEX.test(requestUuid)) return null;
  const targetUuid = rctx.userId.toLowerCase();
  let requestFirst8Sum = 0;
  let targetFirst8Sum = 0;
  for (let i = 0; i < 8; i++) {
    const requestCode = requestUuid.charCodeAt(i);
    requestFirst8Sum += requestCode <= 57 ? requestCode - 48 : requestCode - 87;
    const targetCode = targetUuid.charCodeAt(i);
    targetFirst8Sum += targetCode <= 57 ? targetCode - 48 : targetCode - 87;
  }
  if (requestFirst8Sum === targetFirst8Sum && requestUuid.slice(-12) === targetUuid.slice(-12)) {
    return jsonResponse({ Version: EDT_VERSION }, 200, false);
  }
  return null;
}

export async function handleHttpRoute(rctx: RequestContext): Promise<Response | null> {
  const { url, env } = rctx;
  const requestPath = url.pathname.slice(1).toLowerCase();

  // —— version 路由（原 L76，位于传输分发与门禁之前）——
  if (requestPath === 'version') {
    const versionResp = handleVersion(rctx);
    if (versionResp) return versionResp;
    // uuid 校验失败 → 落到后续分支（原实现：不 return，继续 else-if 链）
  }

  // —— 传输层分发 + 会话编排（原 L89/L93：WS → gRPC/xHTTP，在 http→https 与门禁之前）——
  const transport = selectTransport(rctx.request, rctx);
  if (transport) {
    const accepted = await transport.accept(rctx.request, rctx);
    if (!accepted.ok) return accepted.response;

    const proxyCtx = buildProxyContext(rctx, url, rctx.defaultProxyIP, rctx.defaultProxyFallback);
    const isXhttp = transport.name === 'xhttp';

    if (isXhttp) {
      // xHTTP：first-packet 模式 —— 编排器可能短路（测速 204 / UDP 400 / 拨号 502）
      const result = await runSession({
        rctx,
        transportName: transport.name,
        session: accepted.session,
        earlyData: accepted.session.earlyData,
        proxyCtx,
        socks5Whitelist: rctx.socks5Whitelist,
        mode: 'first-packet',
        respondFirstPacket: (opts) => accepted.respond(opts),
      });
      if (result.kind === 'response') return result.response;
      // started：流式响应（首包已处理，泵已启动）
      return accepted.respond();
    }

    // WS / gRPC：immediate —— 立即返回（101 / 流式 200），首包与泵在后台处理。
    // 绝不能 await runSession：WS 客户端要先收到 101 才会发首包，await 会死锁。
    const response = accepted.respond();
    void runSession({
      rctx,
      transportName: transport.name,
      session: accepted.session,
      earlyData: accepted.session.earlyData,
      proxyCtx,
      socks5Whitelist: rctx.socks5Whitelist,
      mode: 'immediate',
    }).catch((err) => {
      rctx.error('session', `会话失败: ${(err as Error).message}`);
      try {
        accepted.session.close('session error');
      } catch {
        /* ignore */
      }
    });
    return response;
  }

  // L103：http → https 301
  if (url.protocol === 'http:') {
    return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
  }

  // L104：未配置管理密码 → noADMIN 兜底页（任意路径，含 /login）
  if (!rctx.adminPassword) return serveErrorPage(rctx, '/pages/noADMIN.html');

  // L105：KV 绑定门
  if (env.KV && typeof env.KV.get === 'function') {
    // —— 主路由插件链（原 else-if 链中由插件认领的分支，顺序等价）：
    //    fast-sub(L107) / sub(L325) / locations(L518) / admin 子 API(L132-317)——
    for (const plugin of getRoutePlugins()) {
      const pluginResponse = await plugin.onRoute?.(rctx);
      if (pluginResponse) return pluginResponse;
    }
    // L111 登录
    if (requestPath === 'login') return handleLogin(rctx);
    // L127 管理后台（cookie 门禁在 handleAdmin 内；子 API 已被插件链认领）
    if (requestPath === 'admin' || requestPath.startsWith('admin/')) return handleAdmin(rctx);
    // L321 登出 / 访问 /<uuid> 清 cookie
    if (requestPath === 'logout' || UUID_REGEX.test(requestPath)) return handleLogout();
    // L522 robots.txt
    if (requestPath === 'robots.txt') {
      return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
    }
  } else if (!(env.UUID || env.uuid)) {
    // L523：无 KV 且无 envUUID → noKV 兜底页
    return serveErrorPage(rctx, '/pages/noKV.html');
  }

  // —— 兜底插件链（原 L526+：伪装页 nginx/1101/反代）——
  for (const plugin of getFallbackPlugins()) {
    const fallbackResponse = await plugin.onRoute?.(rctx);
    if (fallbackResponse) return fallbackResponse;
  }
  // 未匹配且无兜底插件 → 返回 null，由 index.ts 落 ASSETS / 404
  return null;
}
