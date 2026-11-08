/**
 * P2 配置系统测试 —— 从 test_rename.mjs 配置用例复刻（DESIGN.md §9/§10 P2 验收）。
 * 覆盖：键迁移往返、loadConfig 中文键 KV、toLegacyConfig、GET/POST /admin/config.json 集成。
 */
import { describe, expect, it } from 'vitest';
import { CONFIG_KEY_CN_TO_EN, CONFIG_KEY_EN_TO_CN, migrateConfigKeysDeep, toLegacyConfig } from '../src/config/key-migration';
import { loadConfig } from '../src/config/loader';
import { RequestContext } from '../src/context';
import { md5Md5 } from '../src/services/md5';
import { getPlugins } from '../src/plugins/registry';
import type { Env, KVLike } from '../src/env';
import type { Config } from '../src/config/schema';
import type { Plugin } from '../src/plugins/base';
import worker from '../src/index';

/** 与 test_rename.mjs 相同的 legacy 中文键配置夹具 */
const legacy = {
  UUID: 'x',
  HOST: 'a.example.com',
  '协议类型': 'vless',
  '传输协议': 'ws',
  '跳过证书验证': false,
  '随机路径': true,
  '订阅转换配置': { SUBAPI: 'https://x', UDP: false },
  '反代': {
    PROXYIP: 'auto',
    SOCKS5: { '启用': null, '全局': false, '账号': '', '白名单': ['*a.com'] },
    '路径模板': { PROXYIP: 'proxyip={{IP:PORT}}' },
  },
  '优选订阅生成': { local: true, '本地IP库': { '随机IP': true, '随机数量': 16, '指定端口': -1 }, SUBNAME: 'edgetunnel' },
  TG: { '启用': false, BotToken: null },
  SS: { '加密方式': 'aes-128-gcm', TLS: true },
};

/** 锶序无关的结构化字符串（键序在改名后会变，不能用 JSON 全等） */
function stable(v: unknown): string {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v as object).sort().map((k) => JSON.stringify(k) + ':' + stable((v as Record<string, unknown>)[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

function makeKv(store: Map<string, string>): KVLike {
  return {
    get: async (key) => store.get(key) ?? null,
    put: async (key, value) => {
      store.set(key, value);
    },
  };
}

function makeRctx(env: Env, url = 'https://a.example.com/', ua = 'test-agent'): RequestContext {
  const request = new Request(url, { headers: { 'User-Agent': ua } });
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
  return new RequestContext(request, env, ctx);
}

describe('配置键名迁移（CN↔EN 往返）', () => {
  it('CN→EN：顶层与嵌套键全部转换，无中文键残留', () => {
    const migrated = migrateConfigKeysDeep(structuredClone(legacy), CONFIG_KEY_CN_TO_EN) as unknown as Config;
    expect(migrated.protocolType).toBe('vless');
    expect(migrated.proxy.SOCKS5.enabled).toBeNull();
    expect(migrated.bestSubGen.localIPPool.randomCount).toBe(16);
    expect(JSON.stringify(migrated)).not.toContain('协议类型');
    expect(JSON.stringify(migrated)).not.toContain('白名单');
  });

  it('EN→CN 往返等于原 legacy（键序无关），且 toLegacyConfig 返回副本', () => {
    const migrated = migrateConfigKeysDeep(structuredClone(legacy), CONFIG_KEY_CN_TO_EN) as unknown as Config;
    const back = toLegacyConfig(migrated) as unknown as typeof legacy;
    expect(stable(back)).toBe(stable(legacy));
    expect(back).not.toBe(migrated);
    expect(migrated.protocolType).toBe('vless'); // 原对象未被 toLegacy 污染
  });

  it('映射表双向一致（85 对，EN→CN∘CN→EN = 恒等）', () => {
    expect(Object.keys(CONFIG_KEY_CN_TO_EN).length).toBe(85);
    expect(Object.keys(CONFIG_KEY_EN_TO_CN).length).toBe(85);
    // CN→EN 再 EN→CN 应还原
    const round = migrateConfigKeysDeep(structuredClone(legacy), CONFIG_KEY_CN_TO_EN);
    const back = migrateConfigKeysDeep(round, CONFIG_KEY_EN_TO_CN);
    expect(stable(back)).toBe(stable(legacy));
  });
});

describe('loadConfig（legacy 中文键 KV）', () => {
  it('读入迁移为英文键、保留嵌套值、计算 TOKEN，且不回写 KV', async () => {
    const store = new Map<string, string>([['config.json', JSON.stringify(legacy, null, 2)]]);
    const env: Env = { KV: makeKv(store), HOST: 'a.example.com', UUID: '00000000-0000-4000-8000-000000000000' };
    const rctx = makeRctx(env);

    const loaded = await loadConfig(rctx);
    expect(loaded.protocolType).toBe('vless');
    expect(loaded.proxy.SOCKS5.whitelist[0]).toBe('*a.com');
    expect(typeof loaded.bestSubGen.TOKEN).toBe('string');
    expect(loaded.UUID).toBe('00000000-0000-4000-8000-000000000000');

    // KV 中仍是中文键（loadConfig 只迁移内存副本，除非 fresh-init）
    expect(JSON.parse(store.get('config.json')!)['协议类型']).toBe('vless');
    // 副作用：TG/CF 默认文件初始化
    expect(store.has('tg.json')).toBe(true);
    expect(store.has('cf.json')).toBe(true);
  });

  it('toLegacyConfig 视图：转回中文键且不修改 loaded', async () => {
    const store = new Map<string, string>([['config.json', JSON.stringify(legacy, null, 2)]]);
    const env: Env = { KV: makeKv(store), HOST: 'a.example.com', UUID: '00000000-0000-4000-8000-000000000000' };
    const loaded = await loadConfig(makeRctx(env));

    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy 视图是异构中文键对象，逐字段断言用宽松类型
    const forUi = toLegacyConfig(loaded) as any;
    expect(forUi['协议类型']).toBe('vless');
    expect(forUi['反代'].SOCKS5['白名单'][0]).toBe('*a.com');
    expect(loaded.protocolType).toBe('vless'); // 原对象未被改
  });

  it('fresh-init：KV 无 config.json 时写入英文键默认配置', async () => {
    const store = new Map<string, string>();
    const env: Env = { KV: makeKv(store), HOST: 'fresh.example.com', UUID: '00000000-0000-4000-8000-000000000000' };
    const loaded = await loadConfig(makeRctx(env));

    expect(store.has('config.json')).toBe(true);
    const saved = JSON.parse(store.get('config.json')!);
    expect(saved.protocolType).toBe('vless');
    expect(saved['协议类型']).toBeUndefined();
    expect(loaded.HOST).toBe('fresh.example.com');
    expect(loaded.LINK).toContain('vless://');
    expect(loaded.fullNodePath).toBe('/');
  });

  it('插件 onConfigLoad 钩子在 loadConfig 末尾执行', async () => {
    const store = new Map<string, string>([['config.json', JSON.stringify(legacy, null, 2)]]);
    const env: Env = { KV: makeKv(store), HOST: 'a.example.com', UUID: '00000000-0000-4000-8000-000000000000' };
    const rctx = makeRctx(env);

    let called = false;
    const plugins: Plugin[] = [
      {
        name: 'test-hook',
        async onConfigLoad(cfg) {
          called = true;
          return { ...cfg, Fingerprint: 'firefox' };
        },
      },
    ];
    const loaded = await loadConfig(rctx, { plugins });
    expect(called).toBe(true);
    expect(loaded.Fingerprint).toBe('firefox');
    // 显式 plugins 列表不污染全局注册表（全局仅含 P7 注册的内置插件，无 test-hook）
    expect(getPlugins().some((p) => p.name === 'test-hook')).toBe(false);
  });
});

describe('集成：GET/POST /admin/config.json', () => {
  const adminPassword = 'secret-pass';
  const key = 'test-key-value';
  const ua = 'TestUA/1.0';
  const authCookie = md5Md5(ua + key + adminPassword);

  function makeStore(): Map<string, string> {
    return new Map<string, string>([['config.json', JSON.stringify(legacy, null, 2)]]);
  }

  function makeEnv(store: Map<string, string>): Env {
    return {
      KV: makeKv(store),
      ADMIN: adminPassword,
      KEY: key,
      HOST: 'a.example.com',
      ASSETS: {
        fetch: async () => new Response('<html>stub</html>', { headers: { 'Content-Type': 'text/html; charset=UTF-8' } }),
      } as unknown as NonNullable<Env['ASSETS']>,
    };
  }

  const execCtx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

  function attachCf<T extends Request>(req: T): T {
    Object.assign(req, { cf: { colo: 'HKG', asn: 13335, asOrganization: 'Cloudflare', country: 'US', city: 'San Jose' } });
    return req;
  }

  it('GET /admin/config.json：合法 cookie → 200，中文键响应，不泄漏英文键', async () => {
    const store = makeStore();
    const req = attachCf(
      new Request('https://a.example.com/admin/config.json', {
        headers: { 'user-agent': ua, cookie: `auth=${authCookie}` },
      }),
    );
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    const body = (await resp.json()) as Record<string, unknown>;

    expect(resp.status).toBe(200);
    expect(body['协议类型']).toBe('vless');
    expect(body['反代']).toBeTruthy();
    expect((body['反代'] as Record<string, unknown>).SOCKS5).toBeTruthy();
    expect(body.protocolType).toBeUndefined();
  });

  it('GET /admin/config.json：无 cookie → 302 /login', async () => {
    const store = makeStore();
    const req = attachCf(new Request('https://a.example.com/admin/config.json', { headers: { 'user-agent': ua } }));
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(302);
    expect(resp.headers.get('Location')).toBe('/login');
  });

  it('POST /admin/config.json：中文键 body → 200，KV 落英文键', async () => {
    const store = makeStore();
    const postBody = JSON.parse(JSON.stringify(legacy)) as Record<string, unknown>;
    postBody.UUID = '00000000-0000-4000-8000-000000000000';
    postBody.HOST = 'a.example.com';
    const req = attachCf(
      new Request('https://a.example.com/admin/config.json', {
        method: 'POST',
        headers: { 'user-agent': ua, cookie: `auth=${authCookie}`, 'content-type': 'application/json' },
        body: JSON.stringify(postBody),
      }),
    );
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    const result = (await resp.json()) as { success?: boolean };

    expect(resp.status).toBe(200);
    expect(result.success).toBe(true);
    const saved = JSON.parse(store.get('config.json')!) as Record<string, unknown>;
    expect(saved.protocolType).toBe('vless');
    expect(saved['协议类型']).toBeUndefined();
  });

  it('POST /admin/config.json：缺 UUID/HOST → 400 配置不完整', async () => {
    const store = makeStore();
    const req = attachCf(
      new Request('https://a.example.com/admin/config.json', {
        method: 'POST',
        headers: { 'user-agent': ua, cookie: `auth=${authCookie}`, 'content-type': 'application/json' },
        body: JSON.stringify({ '协议类型': 'trojan' }),
      }),
    );
    const resp = await worker.fetch(req, makeEnv(store), execCtx);
    expect(resp.status).toBe(400);
    const body = (await resp.json()) as { error?: string };
    expect(body.error).toBe('配置不完整');
  });

  it('无 ADMIN 环境 → 任意路径落 noADMIN 兜底页（404）', async () => {
    const store = makeStore();
    const env = makeEnv(store);
    delete env.ADMIN;
    delete env.KEY;
    delete env.UUID;
    const req = new Request('https://a.example.com/anything', { headers: { 'user-agent': ua } });
    const resp = await worker.fetch(req, env, execCtx);
    expect(resp.status).toBe(404);
    expect(resp.headers.get('Cache-Control')).toContain('no-store');
  });
});
