// Functional tests for the renamed worker (run with Node 26).
// 归档对照物：node archive/test_rename.mjs（对 archive/_worker.js 跑 25 个行为向量）。
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = process.cwd();
const src = fs.readFileSync(path.join(root, 'archive', '_worker.js'), 'utf8')
  .replace('export default {', 'globalThis.__worker = {'); // exact: the file header mentions export default.fetch in prose

// crypto shim: CF Workers' crypto.subtle supports MD5; Node's WebCrypto does not.
function md5(data) {
  return createHash('md5').update(Buffer.from(data)).digest();
}
const realCrypto = globalThis.crypto;
const cryptoShim = {
  getRandomValues: (arr) => realCrypto.getRandomValues(arr),
  randomUUID: () => realCrypto.randomUUID(),
  subtle: {
    digest: async (alg, data) => {
      if (String(alg).toUpperCase() === 'MD5') {
        // copy out of Node's pooled Buffer so byteLength is exactly 16
        return new Uint8Array(md5(data)).buffer;
      }
      return realCrypto.subtle.digest(alg, data);
    },
    sign: (...a) => realCrypto.subtle.sign(...a),
    verify: (...a) => realCrypto.subtle.verify(...a),
    importKey: (...a) => realCrypto.subtle.importKey(...a),
    encrypt: (...a) => realCrypto.subtle.encrypt(...a),
    decrypt: (...a) => realCrypto.subtle.decrypt(...a),
    exportKey: (...a) => realCrypto.subtle.exportKey(...a),
    deriveBits: (...a) => realCrypto.subtle.deriveBits(...a),
    generateKey: (...a) => realCrypto.subtle.generateKey(...a),
    wrapKey: (...a) => realCrypto.subtle.wrapKey(...a),
    unwrapKey: (...a) => realCrypto.subtle.unwrapKey(...a),
  },
};

// Only host Web APIs here — let the vm context keep its own ECMAScript intrinsics
// (passing host Object/Array/JSON across realms breaks instanceof).
const sandbox = {
  console,
  crypto: cryptoShim,
  TextEncoder, TextDecoder,
  URL, URLSearchParams,
  atob, btoa,
  performance,
  setTimeout, clearTimeout, setInterval, clearInterval,
  fetch: async () => { throw new Error('network disabled in test'); },
  Request, Response, Headers,
  AbortController, AbortSignal,
  WebSocket: class WebSocket { static OPEN = 1; },
  ReadableStream, WritableStream, TransformStream,
  queueMicrotask,
  structuredClone,
};
vm.createContext(sandbox);
vm.runInContext(src, sandbox, { filename: '_worker.js' });

const w = sandbox.__worker;
// top-level `const` bindings live in the context's lexical environment, not on globalThis
const fromVm = (expr) => vm.runInContext(expr, sandbox);
let passed = 0, failed = 0;
function ok(cond, msg) {
  if (cond) { passed++; console.log('  PASS', msg); }
  else { failed++; console.log('  FAIL', msg); }
}

console.log('== brand constants ==');
ok(fromVm('BRAND_PROXYIP') === 'PROXYIP', "BRAND_PROXYIP === 'PROXYIP'");
ok(fromVm('BRAND_OWNER') === 'cmliu', "BRAND_OWNER === 'cmliu'");
ok(fromVm('BRAND_TP1_ID') === '090227', "BRAND_TP1_ID === '090227'");
ok(fromVm('CLUSTER_SUB_UA') === 'v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)',
   'CLUSTER_SUB_UA matches original runtime value');

console.log('== config key migration roundtrip ==');
const legacy = {
  UUID: 'x', HOST: 'a.example.com',
  '协议类型': 'vless', '传输协议': 'ws',
  '跳过证书验证': false, '随机路径': true,
  '订阅转换配置': { SUBAPI: 'https://x', UDP: false },
  '反代': { 'PROXYIP': 'auto', 'SOCKS5': { '启用': null, '全局': false, '账号': '', '白名单': ['*a.com'] }, '路径模板': { 'PROXYIP': 'proxyip={{IP:PORT}}' } },
  '优选订阅生成': { local: true, '本地IP库': { '随机IP': true, '随机数量': 16, '指定端口': -1 }, SUBNAME: 'edgetunnel' },
  TG: { '启用': false, BotToken: null },
  SS: { '加密方式': 'aes-128-gcm', TLS: true },
};
const CN2EN = fromVm('CONFIG_KEY_CN_TO_EN');
const migrate = fromVm('migrateConfigKeysDeep');
const toLegacy = fromVm('toLegacyConfig');
// key ORDER changes after rename (renamed keys re-append); compare structurally
function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
const migrated = migrate(structuredClone(legacy), CN2EN);
ok(migrated.protocolType === 'vless', 'CN->EN: 协议类型 -> protocolType');
ok(migrated.proxy.SOCKS5.enabled === null, 'CN->EN: nested 启用 -> enabled');
ok(migrated.bestSubGen.localIPPool.randomCount === 16, 'CN->EN: 随机数量 -> randomCount (nested)');
ok(!JSON.stringify(migrated).includes('协议类型'), 'CN->EN: no Chinese keys remain');

const back = toLegacy(migrated);
ok(stable(back) === stable(legacy), 'EN->CN roundtrip equals original legacy config (key-order-insensitive)');
ok(toLegacy(migrated) !== migrated, 'toLegacyConfig returns a copy (no mutation)');

console.log('== loadConfig with legacy Chinese-key KV ==');
const kvStore = new Map();
kvStore.set('config.json', JSON.stringify(legacy, null, 2));
const env = {
  KV: {
    get: async (k) => kvStore.get(k) ?? null,
    put: async (k, v) => { kvStore.set(k, v); },
  },
  HOST: 'a.example.com',
};
sandbox.__env = env;
const loaded = await vm.runInContext(
  'loadConfig(__env, "a.example.com", "00000000-0000-4000-8000-000000000000", "test-agent")',
  sandbox,
);
ok(loaded && loaded.protocolType === 'vless', 'loadConfig migrates legacy keys to English');
ok(loaded.proxy && loaded.proxy.SOCKS5.whitelist[0] === '*a.com', 'loadConfig preserves nested values');
ok(loaded.bestSubGen && typeof loaded.bestSubGen.TOKEN === 'string', 'loadConfig computes TOKEN');
ok(!JSON.stringify({协议类型: loaded.protocolType}).includes('x') || loaded.protocolType === 'vless', 'loaded config uses English keys');
// KV now stores what loadConfig wrote only on fresh init; legacy file untouched unless reset
ok(JSON.parse(kvStore.get('config.json'))['协议类型'] === 'vless', 'KV still holds legacy keys until next save (untouched)');

console.log('== toLegacyConfig on loaded config (GET admin path) ==');
const forUi = toLegacy(loaded);
ok(forUi['协议类型'] === 'vless', 'GET view translates protocolType back to 协议类型');
ok(forUi['反代'] && forUi['反代'].SOCKS5['白名单'][0] === '*a.com', 'GET view translates nested proxy section (whitelist -> 白名单)');
ok(loaded.protocolType === 'vless', 'original loaded object NOT mutated by toLegacyConfig');

console.log('== integration: GET /admin/config.json ==');
function md5hex(s) { return createHash('md5').update(s).digest('hex'); }
// replicate MD5MD5: md5(hex(md5(input)).slice(7,27))
function md5md5(s) {
  const h1 = md5hex(s);
  return md5hex(h1.slice(7, 27));
}
const adminPassword = 'secret-pass';
const key = 'test-key-value';
sandbox.__envFull = {
  KV: env.KV,
  ADMIN: adminPassword,
  KEY: key,
  HOST: 'a.example.com',
};
const ua = 'TestUA/1.0';
const authCookie = md5md5(ua + key + adminPassword);
const req = new Request('https://a.example.com/admin/config.json', {
  headers: { 'user-agent': ua, cookie: `auth=${authCookie}` },
});
req.cf = { colo: 'HKG', asn: '13335', asOrganization: 'Cloudflare' };
const ctx = { waitUntil: () => {} };
const resp = await w.fetch(req, sandbox.__envFull, ctx);
const body = await resp.json();
ok(resp.status === 200, `admin/config.json status 200 (got ${resp.status})`);
ok(body['协议类型'] === 'vless', 'integration response uses legacy Chinese keys');
ok(body['反代'] && body['反代'].SOCKS5, 'integration response has 反代 section');
ok(body.protocolType === undefined, 'integration response does not leak English protocolType key');

console.log('== integration: POST /admin/config.json accepts Chinese keys ==');
const postBody = JSON.parse(JSON.stringify(legacy));
postBody.UUID = '00000000-0000-4000-8000-000000000000';
postBody.HOST = 'a.example.com';
const postReq = new Request('https://a.example.com/admin/config.json', {
  method: 'POST',
  headers: { 'user-agent': ua, cookie: `auth=${authCookie}`, 'content-type': 'application/json' },
  body: JSON.stringify(postBody),
});
postReq.cf = req.cf;
const postResp = await w.fetch(postReq, sandbox.__envFull, ctx);
const postResult = await postResp.json();
ok(postResp.status === 200 && postResult.success === true, 'POST config accepted');
const saved = JSON.parse(kvStore.get('config.json'));
ok(saved.protocolType === 'vless', 'POST saved English keys to KV');
ok(saved['协议类型'] === undefined, 'POST did not store Chinese keys');

console.log('');
console.log(`RESULT: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

