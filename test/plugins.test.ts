/**
 * P7 插件四件套测试（DESIGN.md §10 P7 验收）。
 * 覆盖：base64Secret 编解码、fast-sub、/sub（token 体系 + 本地生成）、
 * admin 子 API（log/check/getADDAPI/ADD/cf/tg）、locations、伪装页、/video/ 链式解析。
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RequestContext } from '../src/context';
import { md5Md5 } from '../src/services/md5';
import { base64SecretEncode, base64SecretDecode } from '../src/services/base64-secret';
import { buildProxyContext } from '../src/forward/proxy-ctx';
import { DEFAULT_ENCRYPTION_SECRET } from '../src/context';
import type { Env, KVLike } from '../src/env';
import worker from '../src/index';

const ADMIN = 'secret-pass';
const KEY = 'test-key-value';
const UUID = '00000000-0000-4000-8000-000000000000';
const HOST = 'a.example.com';
const UA = 'TestUA/1.0';
const AUTH_COOKIE = md5Md5(UA + KEY + ADMIN);

function makeKv(store: Map<string, string>): KVLike {
  return {
    get: async (key) => store.get(key) ?? null,
    put: async (key, value) => {
      store.set(key, value);
    },
  };
}

function makeEnv(store: Map<string, string>, extra: Env = {}): Env {
  return { KV: makeKv(store), ADMIN, KEY, HOST: HOST, UUID, ...extra };
}

const execCtx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

function attachCf<T extends Request>(req: T): T {
  Object.assign(req, { cf: { colo: 'HKG', asn: 13335, asOrganization: 'Cloudflare', country: 'US', city: 'San Jose' } });
  return req;
}

function makeRctx(env: Env, url: string, ua = UA): RequestContext {
  const request = attachCf(new Request(url, { headers: { 'User-Agent': ua, cookie: `auth=${AUTH_COOKIE}` } }));
  return new RequestContext(request, env, execCtx);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('base64Secret 编解码（订阅 token 种子 / /video/ 链式路径）', () => {
  it('encode → decode 往返还原', () => {
    const plain = JSON.stringify({ type: 'socks5', hostname: '1.2.3.4', port: 1080 });
    expect(base64SecretDecode(base64SecretEncode(plain, UUID), UUID)).toBe(plain);
  });

  it('与原实现算法一致（秘钥 XOR → btoa）', () => {
    const plain = 'hello xtunnel';
    const secret = 'abc';
    const keyBytes = new TextEncoder().encode(secret);
    const plainBytes = new TextEncoder().encode(plain);
    let binary = '';
    for (let i = 0; i < plainBytes.length; i++) binary += String.fromCharCode(plainBytes[i]! ^ keyBytes[i % keyBytes.length]!);
    expect(base64SecretEncode(plain, secret)).toBe(btoa(binary));
  });
});

describe('fast-sub 快速订阅（原 L107）', () => {
  it('路径等于 KEY → 302 /sub?token=MD5MD5(host+uuid)，保留原查询参数', async () => {
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/${KEY}?t=1`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(302);
    expect(resp.headers.get('Location')).toBe(`/sub?t=1&token=${md5Md5(HOST + UUID)}`);
  });

  it('KEY 为默认值时 fast-sub 禁用（落伪装页）', async () => {
    const store = new Map<string, string>();
    const env = makeEnv(store);
    delete env.KEY;
    const req = attachCf(new Request(`https://${HOST}/${encodeURIComponent(DEFAULT_ENCRYPTION_SECRET)}`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, env, execCtx);
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain('Welcome to nginx!');
  });
});

describe('/sub 订阅（原 L325-517）', () => {
  function stubFetchThrow(): void {
    vi.stubGlobal('fetch', async () => {
      throw new Error('network disabled in test');
    });
  }

  it('客户端 token → 200，头齐全，base64 正文为 vless 节点且占位 host 已替换', async () => {
    stubFetchThrow();
    const store = new Map<string, string>();
    const token = md5Md5(HOST + UUID);
    const req = attachCf(new Request(`https://${HOST}/sub?token=${token}`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);

    expect(resp.status).toBe(200);
    expect(resp.headers.get('content-type')).toBe('text/plain; charset=utf-8');
    expect(resp.headers.get('Profile-Update-Interval')).toBe('3');
    expect(resp.headers.get('Profile-web-page-url')).toBe(`https://${HOST}/admin`);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Content-Disposition')).toContain('attachment');

    const decoded = atob(await resp.text());
    expect(decoded).toContain('vless://');
    expect(decoded).toContain(`00000000-0000-4000-8000-000000000000@`); // uuid@地址:端口
    expect(decoded).toMatch(/00000000-0000-4000-8000-000000000000@[\d.]+:\d+\?/);
    expect(decoded).toContain('sni=a.example.com'); // example.com 占位替换
    expect(decoded).not.toContain('sni=example.com');
  });

  it('日切后端 token → 200（兼容红线：种子 = base64Secret(MD5MD5(host+uuid), uuid)）', async () => {
    stubFetchThrow();
    const store = new Map<string, string>();
    const subToken = md5Md5(HOST + UUID);
    const seed = base64SecretEncode(subToken, UUID);
    const today = md5Md5(seed + Math.floor(Date.now() / 86400000));
    const req = attachCf(new Request(`https://${HOST}/sub?token=${today}`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('content-type')).toBe('text/plain; charset=utf-8'); // 防御 nginx 伪装页假阳性
    expect(resp.headers.get('Profile-Update-Interval')).toBe('3');
  });

  it('优选生成器哨兵（BEST_SUB + 固定哨兵参数 + 集群 UA）→ 200 且不写 Get_SUB 日志', async () => {
    stubFetchThrow();
    const store = new Map<string, string>();
    const env = makeEnv(store, { BEST_SUB: '1' });
    const req = attachCf(
      new Request(`https://${HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`, {
        headers: { 'User-Agent': 'v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)' },
      }),
    );
    const resp = await worker.fetch(req, env, execCtx);
    expect(resp.status).toBe(200);
    await new Promise((r) => setTimeout(r, 20));
    expect(store.has('log.json')).toBe(false); // Get_Best_SUB writeKvLog=false
  });

  it('token 不匹配 → 落出分支到伪装页（nginx）', async () => {
    stubFetchThrow();
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/sub?token=bad-token`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain('Welcome to nginx!');
  });
});

describe('admin 子 API（AdminUiPlugin / BestIpPlugin）', () => {
  function authedReq(path: string, init: RequestInit = {}): Request {
    return attachCf(
      new Request(`https://${HOST}${path}`, { headers: { 'User-Agent': UA, cookie: `auth=${AUTH_COOKIE}` }, ...init }),
    );
  }

  it('log.json：有效 cookie → 200 KV 内容；无效 cookie → 302 /login', async () => {
    const store = new Map<string, string>([['log.json', '[{"TYPE":"Get_SUB"}]']]);
    const ok = await worker.fetch(authedReq('/admin/log.json'), makeEnv(store), execCtx);
    expect(ok.status).toBe(200);
    expect(await ok.text()).toBe('[{"TYPE":"Get_SUB"}]');

    const bad = await worker.fetch(
      attachCf(new Request(`https://${HOST}/admin/log.json`, { headers: { 'User-Agent': UA } })),
      makeEnv(store),
      execCtx,
    );
    expect(bad.status).toBe(302);
    expect(bad.headers.get('Location')).toBe('/login');
  });

  it('check：缺代理参数 → 400', async () => {
    const store = new Map<string, string>();
    const resp = await worker.fetch(authedReq('/admin/check'), makeEnv(store), execCtx);
    expect(resp.status).toBe(400);
    expect(((await resp.json()) as { error: string }).error).toBe('缺少代理参数');
  });

  it('check：Node 环境无 fetcher → 200 success:false（恒 200 语义）', async () => {
    const store = new Map<string, string>();
    const resp = await worker.fetch(authedReq('/admin/check?socks5=u:p@1.2.3.4:1080'), makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { success: boolean; proxy: string; error: string };
    expect(body.success).toBe(false);
    expect(body.proxy).toBe('socks5://u:p@1.2.3.4:1080');
    expect(body.error).toBeTruthy();
  });

  it('getCloudflareUsage：无凭据 → 200 success:false', async () => {
    const store = new Map<string, string>();
    const resp = await worker.fetch(authedReq('/admin/getCloudflareUsage'), makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { success: boolean };
    expect(body.success).toBe(false);
  });

  it('getADDAPI：无 url → 403；带 url → 200 解析出的节点列表', async () => {
    const store = new Map<string, string>();
    const none = await worker.fetch(authedReq('/admin/getADDAPI'), makeEnv(store), execCtx);
    expect(none.status).toBe(403);
    expect(((await none.json()) as { success: boolean }).success).toBe(false);

    vi.stubGlobal('fetch', async () => new Response('1.2.3.4\n5.6.7.8', { headers: { 'content-type': 'text/plain' } }));
    const ok = await worker.fetch(authedReq(`/admin/getADDAPI?url=${encodeURIComponent('https://api.example.com/ips')}`), makeEnv(store), execCtx);
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { success: boolean; data: string[] };
    expect(body.success).toBe(true);
    expect(body.data).toEqual(['1.2.3.4:443', '5.6.7.8:443']);
  });

  it('getADDAPI：url 非法 → 500 带原因', async () => {
    const store = new Map<string, string>();
    const resp = await worker.fetch(authedReq('/admin/getADDAPI?url=not-a-url'), makeEnv(store), execCtx);
    expect(resp.status).toBe(500);
    const body = (await resp.json()) as { msg: string };
    expect(body.msg).toContain('验证优选API失败');
  });

  it('ADD.txt：GET 返回 KV 内容与 asn 头；POST 保存', async () => {
    const store = new Map<string, string>([['ADD.txt', '9.9.9.9:2053#测试节点']]);
    const getResp = await worker.fetch(authedReq('/admin/ADD.txt'), makeEnv(store), execCtx);
    expect(getResp.status).toBe(200);
    expect(getResp.headers.get('content-type')).toBe('text/plain;charset=utf-8');
    expect(getResp.headers.get('asn')).toBe('13335');
    expect(await getResp.text()).toBe('9.9.9.9:2053#测试节点');

    const postResp = await worker.fetch(
      authedReq('/admin/ADD.txt', { method: 'POST', body: '1.1.1.1:443#新IP' }),
      makeEnv(store),
      execCtx,
    );
    expect(postResp.status).toBe(200);
    expect(((await postResp.json()) as { success: boolean }).success).toBe(true);
    expect(store.get('ADD.txt')).toBe('1.1.1.1:443#新IP');
  });

  it('cf.json：GET 返回 request.cf；POST init=true 清空入库', async () => {
    const store = new Map<string, string>();
    const getResp = await worker.fetch(authedReq('/admin/cf.json'), makeEnv(store), execCtx);
    expect(getResp.status).toBe(200);
    expect(((await getResp.json()) as { colo: string }).colo).toBe('HKG');

    const postResp = await worker.fetch(
      authedReq('/admin/cf.json', { method: 'POST', headers: { 'User-Agent': UA, cookie: `auth=${AUTH_COOKIE}`, 'content-type': 'application/json' }, body: JSON.stringify({ init: true }) }),
      makeEnv(store),
      execCtx,
    );
    expect(postResp.status).toBe(200);
    expect(((await postResp.json()) as { success: boolean }).success).toBe(true);
    const saved = JSON.parse(store.get('cf.json')!) as Record<string, unknown>;
    expect(saved.Email).toBeNull();
    expect(saved.UsageAPI).toBeNull();
  });

  it('tg.json POST：缺参 → 400；完整 → 入库', async () => {
    const store = new Map<string, string>();
    const bad = await worker.fetch(
      authedReq('/admin/tg.json', { method: 'POST', headers: { 'User-Agent': UA, cookie: `auth=${AUTH_COOKIE}`, 'content-type': 'application/json' }, body: JSON.stringify({ BotToken: 'x' }) }),
      makeEnv(store),
      execCtx,
    );
    expect(bad.status).toBe(400);

    const ok = await worker.fetch(
      authedReq('/admin/tg.json', { method: 'POST', headers: { 'User-Agent': UA, cookie: `auth=${AUTH_COOKIE}`, 'content-type': 'application/json' }, body: JSON.stringify({ BotToken: 'tok', ChatID: '42' }) }),
      makeEnv(store),
      execCtx,
    );
    expect(ok.status).toBe(200);
    expect(JSON.parse(store.get('tg.json')!)).toEqual({ BotToken: 'tok', ChatID: '42' });
  });
});

describe('locations 反代（原 L518）', () => {
  it('cookie 有效 → 代理 speed.cloudflare.com/locations', async () => {
    vi.stubGlobal('fetch', async () => new Response('[{"id":"hkg"}]', { status: 200 }));
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/locations`, { headers: { 'User-Agent': UA, cookie: `auth=${AUTH_COOKIE}` } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe('[{"id":"hkg"}]');
  });

  it('cookie 无效 → 落伪装页（与原落 else-if 链行为一致）', async () => {
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/locations`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain('Welcome to nginx!');
  });
});

describe('伪装页（FakePagePlugin，原 L526-549）', () => {
  it('未匹配路径 → nginx 欢迎页', async () => {
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/anything/unknown`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toBe('text/html; charset=UTF-8');
    expect(await resp.text()).toContain('Welcome to nginx!');
  });

  it("env.URL='1101' → CF 1101 错误页", async () => {
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/whatever`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store, { URL: '1101' }), execCtx);
    expect(resp.status).toBe(200);
    const html = await resp.text();
    expect(html).toContain('Worker threw exception');
    expect(html).toContain('1101');
    expect(html).toContain(HOST);
  });

  it('env.URL=域名 → 反代源站并替换域名、禁缓存', async () => {
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
      expect(String(input)).toBe(`https://example.com/my/page`);
      return new Response('<html>example.com welcome</html>', { headers: { 'content-type': 'text/html; charset=utf-8' } });
    });
    const store = new Map<string, string>();
    const req = attachCf(new Request(`https://${HOST}/my/page`, { headers: { 'User-Agent': UA } }));
    const resp = await worker.fetch(req, makeEnv(store, { URL: 'example.com' }), execCtx);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(await resp.text()).toBe('<html>a.example.com welcome</html>');
  });
});

describe('/video/<b64> 链式代理路径（原 L6308-6331）', () => {
  it('合法 b64 → 解析为链式代理参数（全局、无兜底）', () => {
    const store = new Map<string, string>();
    const rctx = makeRctx(makeEnv(store), `https://${HOST}/`);
    const payload = base64SecretEncode(
      JSON.stringify({ type: 'socks5', hostname: '1.2.3.4', port: 1080, username: 'u', password: 'p' }),
      UUID,
    );
    const url = new URL(`https://${HOST}/video/${payload}`);
    const proxyCtx = buildProxyContext(rctx, url, rctx.defaultProxyIP, rctx.defaultProxyFallback);
    expect(proxyCtx.proxyType).toBe('socks5');
    expect(proxyCtx.proxyParams).toEqual({ username: 'u', password: 'p', hostname: '1.2.3.4', port: 1080 });
    expect(proxyCtx.proxyIP).toBe('链式代理');
    expect(proxyCtx.proxyGlobal).toBe(true);
    expect(proxyCtx.proxyFallback).toBe(false);
  });

  it('非法 b64 → 解析失败记录日志并回落常规参数', () => {
    const store = new Map<string, string>();
    const rctx = makeRctx(makeEnv(store), `https://${HOST}/`);
    const url = new URL(`https://${HOST}/video/not-valid-b64!!`);
    const proxyCtx = buildProxyContext(rctx, url, rctx.defaultProxyIP, rctx.defaultProxyFallback);
    expect(proxyCtx.proxyType).toBeNull();
    expect(proxyCtx.proxyFallback).toBe(rctx.defaultProxyFallback);
  });
});
