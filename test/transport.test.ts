/**
 * P4 传输层测试 —— 帧编解码 / padding 校验 / early data / 评分选择。
 * WS 的101 握手在 wrangler 冒烟验证（Node 的 Response 不接受 101 状态码）。
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebSocketTransport, decodeWsEarlyData, isValidWsEarlyData } from '../src/transport/websocket';
import { GrpcTransport, GrpcFrameParser, buildGrpcFrame } from '../src/transport/grpc';
import {
  XhttpTransport,
  calcHpackHuffmanByteLength,
  extractXhttpPaddingValue,
  generateXhttpPaddingString,
  verifyXhttpPadding,
} from '../src/transport/xhttp';
import { selectTransport } from '../src/transport/registry';
import { RequestContext } from '../src/context';
import { getIdentity } from '../src/services/identity';
import { sha224 } from '../src/utils/sha224';
import type { Env, KVLike } from '../src/env';

const USER_ID = '00000000-0000-4000-8000-000000000000';

function makeRctx(url: string, init: RequestInit = {}, envOverrides: Record<string, unknown> = {}): { rctx: RequestContext; request: Request } {
  const request = new Request(url, init);
  const env = { ADMIN: 'test-admin', UUID: USER_ID, ...envOverrides } as unknown as Env;
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
  return { rctx: new RequestContext(request, env, ctx), request };
}

function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** 18 字节最小 VLESS 首包：version + uuid + optLen */
function buildVlessEarlyData(uuid: string): Uint8Array {
  const b = new Uint8Array(18);
  b[0] = 0;
  b.set(uuidToBytes(uuid), 1);
  b[17] = 0;
  return b;
}

/** 58 字节 Trojan early data：sha224hex(56) + CRLF */
function buildTrojanEarlyData(uuid: string): Uint8Array {
  const hash = new TextEncoder().encode(sha224(uuid));
  const b = new Uint8Array(58);
  b.set(hash, 0);
  b[56] = 0x0d;
  b[57] = 0x0a;
  return b;
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

// —— Mock WebSocketPair（CF 专有 API，Node 无） ——
class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  readyState = 1;
  binaryType = '';
  sent: unknown[] = [];
  private listeners = new Map<string, Array<(ev: unknown) => void>>();
  accept(_opts?: unknown) {}
  send(data: unknown) {
    this.sent.push(data);
  }
  close(_code?: number, _reason?: string) {
    this.readyState = 3;
    this.dispatch('close', {});
  }
  addEventListener(type: string, fn: (ev: unknown) => void) {
    const arr = this.listeners.get(type) ?? [];
    arr.push(fn);
    this.listeners.set(type, arr);
  }
  removeEventListener(type: string, fn: (ev: unknown) => void) {
    const arr = this.listeners.get(type) ?? [];
    const i = arr.indexOf(fn);
    if (i >= 0) arr.splice(i, 1);
  }
  dispatch(type: string, ev: unknown) {
    for (const fn of this.listeners.get(type) ?? []) fn(ev);
  }
}

function stubWebSocketPair(): { client: MockWebSocket; server: MockWebSocket } {
  let client!: MockWebSocket;
  let server!: MockWebSocket;
  vi.stubGlobal('WebSocketPair', class {
    constructor() {
      client = new MockWebSocket();
      server = new MockWebSocket();
      return { 0: client, 1: server };
    }
  });
  return {
    get client() {
      return client;
    },
    get server() {
      return server;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('评分与 selectTransport', () => {
  it('WS：Upgrade: websocket + adminPassword → 100；否则 0', () => {
    const ws = new WebSocketTransport();
    const a = makeRctx('https://x.test/', { headers: { Upgrade: 'websocket' } });
    expect(ws.score(a.request, a.rctx)).toBe(100);
    const b = makeRctx('https://x.test/', { headers: { Upgrade: 'WebSocket' } }); // 大小写不敏感
    expect(ws.score(b.request, b.rctx)).toBe(100);
    const c = makeRctx('https://x.test/');
    expect(ws.score(c.request, c.rctx)).toBe(0);
    const d = makeRctx('https://x.test/', { headers: { Upgrade: 'websocket' } }, { ADMIN: undefined, UUID: undefined });
    expect(ws.score(d.request, d.rctx)).toBe(0);
  });

  it('gRPC：POST + application/grpc → 80；GET / admin路径 / login / 无密码 / 信号头 → 0', () => {
    const grpc = new GrpcTransport();
    const ok = makeRctx('https://x.test/tunnel', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } });
    expect(grpc.score(ok.request, ok.rctx)).toBe(80);
    // content-type 大小写不敏感
    const ct = makeRctx('https://x.test/t', { method: 'POST', headers: { 'Content-Type': 'Application/gRPC+proto' } });
    expect(grpc.score(ct.request, ct.rctx)).toBe(80);

    const get = makeRctx('https://x.test/t', { method: 'GET', headers: { 'Content-Type': 'application/grpc' } });
    expect(grpc.score(get.request, get.rctx)).toBe(0);
    const adminPath = makeRctx('https://x.test/admin/config.json', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } });
    expect(grpc.score(adminPath.request, adminPath.rctx)).toBe(0);
    const loginPath = makeRctx('https://x.test/login', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } });
    expect(grpc.score(loginPath.request, loginPath.rctx)).toBe(0);
    const noPw = makeRctx('https://x.test/t', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } }, { ADMIN: undefined, UUID: undefined });
    expect(grpc.score(noPw.request, noPw.rctx)).toBe(0);
    // xHTTP 信号头存在 → gRPC 让位
    const [identityHeader] = getIdentity(USER_ID);
    const signal = makeRctx('https://x.test/t', {
      method: 'POST',
      headers: { 'Content-Type': 'application/grpc', [identityHeader]: 'x' },
    });
    expect(grpc.score(signal.request, signal.rctx)).toBe(0);
    // 查询参数信号
    const signalQ = makeRctx(`https://x.test/t?${getIdentity(USER_ID)[1]}=1`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/grpc' },
    });
    expect(grpc.score(signalQ.request, signalQ.rctx)).toBe(0);
  });

  it('xHTTP：POST 兜底 60；GET / 无密码 / admin前缀 / login → 0', () => {
    const xhttp = new XhttpTransport();
    const post = makeRctx('https://x.test/t', { method: 'POST' });
    expect(xhttp.score(post.request, post.rctx)).toBe(60);
    const get = makeRctx('https://x.test/t');
    expect(xhttp.score(get.request, get.rctx)).toBe(0);
    const adminPrefix = makeRctx('https://x.test/admin/config.json', { method: 'POST' });
    expect(xhttp.score(adminPrefix.request, adminPrefix.rctx)).toBe(0);
    const login = makeRctx('https://x.test/login', { method: 'POST' });
    expect(xhttp.score(login.request, login.rctx)).toBe(0);
    const noPw = makeRctx('https://x.test/t', { method: 'POST' }, { ADMIN: undefined, UUID: undefined });
    expect(xhttp.score(noPw.request, noPw.rctx)).toBe(0);
    // 精确 /admin 路径不排除（与原 L93 行为一致）
    const exactAdmin = makeRctx('https://x.test/admin', { method: 'POST' });
    expect(xhttp.score(exactAdmin.request, exactAdmin.rctx)).toBe(60);
  });

  it('selectTransport：按评分选中对应传输；全 0 → undefined', () => {
    const wsReq = makeRctx('https://x.test/', { headers: { Upgrade: 'websocket' } });
    expect(selectTransport(wsReq.request, wsReq.rctx)?.name).toBe('websocket');
    const grpcReq = makeRctx('https://x.test/t', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } });
    expect(selectTransport(grpcReq.request, grpcReq.rctx)?.name).toBe('grpc');
    const xhttpReq = makeRctx('https://x.test/t', { method: 'POST' });
    expect(selectTransport(xhttpReq.request, xhttpReq.rctx)?.name).toBe('xhttp');
    const plainGet = makeRctx('https://x.test/');
    expect(selectTransport(plainGet.request, plainGet.rctx)).toBeUndefined();
  });
});

describe('WS early data 解码与校验', () => {
  it('合法 VLESS early data（18B，UUID 匹配）', () => {
    const packet = buildVlessEarlyData(USER_ID);
    expect(isValidWsEarlyData(packet, USER_ID)).toBe(true);
    const decoded = decodeWsEarlyData(b64url(packet), USER_ID);
    expect(decoded).not.toBeNull();
    expect([...decoded!]).toEqual([...packet]);
  });

  it('合法 Trojan early data（sha224hex + CRLF）', () => {
    const packet = buildTrojanEarlyData(USER_ID);
    expect(isValidWsEarlyData(packet, USER_ID)).toBe(true);
    const decoded = decodeWsEarlyData(b64url(packet), USER_ID);
    expect(decoded).not.toBeNull();
    expect(decoded!.byteLength).toBe(58);
  });

  it('UUID 不匹配的18B 数据 → 校验失败 → null', () => {
    const packet = buildVlessEarlyData('ffffffff-ffff-4fff-bfff-ffffffffffff');
    expect(isValidWsEarlyData(packet, USER_ID)).toBe(false);
    expect(decodeWsEarlyData(b64url(packet), USER_ID)).toBeNull();
  });

  it('随机数据 → null', () => {
    const garbage = new Uint8Array(64).fill(0xaa);
    expect(decodeWsEarlyData(b64url(garbage), USER_ID)).toBeNull();
  });

  it('空 header → null；非法 base64 → null', () => {
    expect(decodeWsEarlyData('', USER_ID)).toBeNull();
    expect(decodeWsEarlyData('!!!not-base64!!!', USER_ID)).toBeNull();
  });

  it('超长 header → 抛错（原 early data is too large）', () => {
    const tooLong = 'A'.repeat(12000); // > WS_EARLY_DATA_MAX_HEADER(10927)
    expect(() => decodeWsEarlyData(tooLong, USER_ID)).toThrow(/too large/);
  });
});

describe('WS accept（mock WebSocketPair）', () => {
  it('建会话：earlyData 提取 + message 进 readable + writable 发送', async () => {
    const pair = stubWebSocketPair();
    const packet = buildVlessEarlyData(USER_ID);
    const { rctx, request } = makeRctx('https://x.test/', {
      headers: { Upgrade: 'websocket', 'sec-websocket-protocol': b64url(packet) },
    });
    const accepted = await new WebSocketTransport().accept(request, rctx);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;
    expect(accepted.session.name).toBe('websocket');
    // earlyData 是带外数据，不在 readable 中
    expect(accepted.session.earlyData).not.toBeNull();
    expect([...accepted.session.earlyData!]).toEqual([...packet]);
    expect(typeof accepted.respond).toBe('function');

    // message 事件 → readable
    const reader = accepted.session.readable.getReader();
    pair.server.dispatch('message', { data: new Uint8Array([9, 9, 9]).buffer });
    const { value } = await reader.read();
    expect([...value!]).toEqual([9, 9, 9]);

    // writable → send
    const writer = accepted.session.writable.getWriter();
    await writer.write(new Uint8Array([7, 8]));
    expect(pair.server.sent[0]).toEqual(new Uint8Array([7, 8]));
    accepted.session.close();
  });

  it('?enc= 存在时禁用 early data（原 ssModeDisableEarlyData）', async () => {
    stubWebSocketPair();
    const packet = buildVlessEarlyData(USER_ID);
    const { rctx, request } = makeRctx('https://x.test/?enc=aes-128-gcm', {
      headers: { Upgrade: 'websocket', 'sec-websocket-protocol': b64url(packet) },
    });
    const accepted = await new WebSocketTransport().accept(request, rctx);
    expect(accepted.ok).toBe(true);
    if (accepted.ok) expect(accepted.session.earlyData).toBeUndefined();
  });

  it('respond() 构造101（Node 不支持101状态码，仅验证尝试；真实101见冒烟）', async () => {
    stubWebSocketPair();
    const { rctx, request } = makeRctx('https://x.test/', { headers: { Upgrade: 'websocket' } });
    const accepted = await new WebSocketTransport().accept(request, rctx);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;
    expect(typeof accepted.respond).toBe('function');
    try {
      const resp = accepted.respond();
      expect(resp.status).toBe(101); // CF 运行时
    } catch (err) {
      // Node：status 必须 200..599 —— 证明代码确实尝试了 101
      expect((err as Error).message).toMatch(/status/);
    }
  });
});

describe('gRPC 帧编解码', () => {
  it('buildGrpcFrame：小 payload 精确字节', () => {
    const frame = buildGrpcFrame(new Uint8Array([1, 2, 3]));
    // [0x00, len=5(4B BE), 0x0a, varint(3), payload]
    expect([...frame]).toEqual([0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 1, 2, 3]);
  });

  it('buildGrpcFrame：200B payload（varint 双字节）', () => {
    const payload = new Uint8Array(200).fill(0xab);
    const frame = buildGrpcFrame(payload);
    // varint(200) = [0xC8, 0x01]; protobufLen = 1+2+200 = 203 = 0xCB
    expect(frame[0]).toBe(0x00);
    expect(frame[1]).toBe(0x00);
    expect(frame[2]).toBe(0x00);
    expect(frame[3]).toBe(0x00);
    expect(frame[4]).toBe(203);
    expect(frame[5]).toBe(0x0a);
    expect(frame[6]).toBe(0xc8);
    expect(frame[7]).toBe(0x01);
    expect(frame.byteLength).toBe(5 + 203);
    expect([...frame.subarray(8)]).toEqual([...payload]);
  });

  it('解析器：build→parse 往返（含 protobuf 剥壳）', () => {
    const payload = new TextEncoder().encode('hello-grpc');
    const parser = new GrpcFrameParser();
    const out = parser.push(buildGrpcFrame(payload));
    expect(out.length).toBe(1);
    expect(new TextDecoder().decode(out[0]!)).toBe('hello-grpc');
  });

  it('解析器：帧跨 push 分片', () => {
    const payload = new Uint8Array([5, 6, 7, 8, 9]);
    const frame = buildGrpcFrame(payload);
    const parser = new GrpcFrameParser();
    expect(parser.push(frame.subarray(0, 4))).toEqual([]); // 头未齐
    expect(parser.push(frame.subarray(4, 7))).toEqual([]); // 仍缺
    const out = parser.push(frame.subarray(7));
    expect(out.length).toBe(1);
    expect([...out[0]!]).toEqual([...payload]);
  });

  it('解析器：一次 push 多帧', () => {
    const f1 = buildGrpcFrame(new Uint8Array([1]));
    const f2 = buildGrpcFrame(new Uint8Array([2]));
    const merged = new Uint8Array(f1.byteLength + f2.byteLength);
    merged.set(f1, 0);
    merged.set(f2, f1.byteLength);
    const out = new GrpcFrameParser().push(merged);
    expect(out.length).toBe(2);
    expect([...out[0]!]).toEqual([1]);
    expect([...out[1]!]).toEqual([2]);
  });

  it('解析器：无 protobuf 包装的裸 payload 原样返回', () => {
    // [0x00, len=2, 0x01, 0x02] —— payload[0] != 0x0a → 不剥壳
    const bare = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02]);
    const out = new GrpcFrameParser().push(bare);
    expect(out.length).toBe(1);
    expect([...out[0]!]).toEqual([1, 2]);
  });

  it('解析器：长度不足暂存，凑齐后输出', () => {
    const payload = new Uint8Array([10, 20, 30]);
    const frame = buildGrpcFrame(payload);
    const parser = new GrpcFrameParser();
    expect(parser.push(frame.subarray(0, frame.byteLength - 1))).toEqual([]);
    const out = parser.push(frame.subarray(frame.byteLength - 1));
    expect(out.length).toBe(1);
    expect([...out[0]!]).toEqual([...payload]);
  });
});

describe('gRPC accept', () => {
  it('建会话：上行剥帧、响应头、下行成帧', async () => {
    const { rctx } = makeRctx('https://x.test/t', { method: 'POST', headers: { 'Content-Type': 'application/grpc' } });
    const frame = buildGrpcFrame(new TextEncoder().encode('hello'));
    const request = new Request('https://x.test/t', {
      method: 'POST',
      headers: { 'Content-Type': 'application/grpc' },
      body: frame,
    });
    const accepted = await new GrpcTransport().accept(request, rctx);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;

    // 上行：帧 → payload
    const reader = accepted.session.readable.getReader();
    const { value } = await reader.read();
    expect(new TextDecoder().decode(value!)).toBe('hello');

    // 响应头
    const resp = accepted.respond();
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toBe('application/grpc');
    expect(resp.headers.get('grpc-status')).toBe('0');
    expect(resp.headers.get('X-Accel-Buffering')).toBe('no');

    // 下行：写 payload → 读到成帧字节
    const writer = accepted.session.writable.getWriter();
    await writer.write(new TextEncoder().encode('world'));
    const respReader = resp.body!.getReader();
    const { value: framed } = await respReader.read();
    expect(framed).toEqual(buildGrpcFrame(new TextEncoder().encode('world')));
    accepted.session.close();
  });

  it('无 body → 400', async () => {
    const { rctx } = makeRctx('https://x.test/t', { method: 'POST' });
    const request = new Request('https://x.test/t', { method: 'POST' });
    const accepted = await new GrpcTransport().accept(request, rctx);
    expect(accepted.ok).toBe(false);
    if (!accepted.ok) expect(accepted.response.status).toBe(400);
  });
});

describe('xHTTP padding 校验', () => {
  const [identityHeader, identityKey] = getIdentity(USER_ID);

  it('calcHpackHuffmanByteLength 边界向量（a=5bit/字符）', () => {
    expect(calcHpackHuffmanByteLength('a'.repeat(155))).toBe(97); // <98
    expect(calcHpackHuffmanByteLength('a'.repeat(156))).toBe(98); // 下界
    expect(calcHpackHuffmanByteLength('a'.repeat(1600))).toBe(1000);
    expect(calcHpackHuffmanByteLength('a'.repeat(1604))).toBe(1003); // >1002
  });

  it('verifyXhttpPadding：无 padding 放行；区间内通过；区间外拒绝', () => {
    const none = new Request('https://x.test/t');
    expect(verifyXhttpPadding(none, identityHeader, identityKey)).toBe(true);

    const passLow = new Request(`https://x.test/t?${identityKey}=${'a'.repeat(156)}`);
    expect(verifyXhttpPadding(passLow, identityHeader, identityKey)).toBe(true);
    const passHigh = new Request(`https://x.test/t?${identityKey}=${'a'.repeat(1600)}`);
    expect(verifyXhttpPadding(passHigh, identityHeader, identityKey)).toBe(true);

    const failLow = new Request(`https://x.test/t?${identityKey}=${'a'.repeat(155)}`);
    expect(verifyXhttpPadding(failLow, identityHeader, identityKey)).toBe(false);
    const failHigh = new Request(`https://x.test/t?${identityKey}=${'a'.repeat(1604)}`);
    expect(verifyXhttpPadding(failHigh, identityHeader, identityKey)).toBe(false);
  });

  it('extractXhttpPaddingValue：头 URL 参数 > 头原值 > 查询参数', () => {
    const fromUrl = new Request('https://x.test/t', {
      headers: { [identityHeader]: `https://x.invalid/?${identityKey}=fromurl` },
    });
    expect(extractXhttpPaddingValue(fromUrl, identityHeader, identityKey)).toBe('fromurl');

    const rawHeader = new Request('https://x.test/t', { headers: { [identityHeader]: 'rawvalue' } });
    expect(extractXhttpPaddingValue(rawHeader, identityHeader, identityKey)).toBe('rawvalue');

    const fromQuery = new Request(`https://x.test/t?${identityKey}=fromquery`);
    expect(extractXhttpPaddingValue(fromQuery, identityHeader, identityKey)).toBe('fromquery');

    expect(extractXhttpPaddingValue(new Request('https://x.test/t'), identityHeader, identityKey)).toBe('');
  });

  it('generateXhttpPaddingString：长度与字符集', () => {
    const s = generateXhttpPaddingString(500);
    expect(s.length).toBe(500);
    expect(s).toMatch(/^[0-9A-Za-z]+$/);
  });
});

describe('xHTTP accept', () => {
  const [identityHeader] = getIdentity(USER_ID);

  it('padding 校验失败 → 400 拒绝', async () => {
    const [h, k] = getIdentity(USER_ID);
    const { rctx } = makeRctx(`https://x.test/t?${k}=${'a'.repeat(155)}`, { method: 'POST' }); // huffman 97 < 98
    const request = new Request(`https://x.test/t?${k}=${'a'.repeat(155)}`, { method: 'POST' });
    const accepted = await new XhttpTransport().accept(request, rctx);
    expect(accepted.ok).toBe(false);
    if (!accepted.ok) expect(accepted.response.status).toBe(400);
    void h;
  });

  it('无 body → 400', async () => {
    const { rctx } = makeRctx('https://x.test/t', { method: 'POST' });
    const request = new Request('https://x.test/t', { method: 'POST' });
    const accepted = await new XhttpTransport().accept(request, rctx);
    expect(accepted.ok).toBe(false);
    if (!accepted.ok) expect(accepted.response.status).toBe(400);
  });

  it('建会话：流式响应含身份头 + body 透传 + 短路响应', async () => {
    const { rctx } = makeRctx('https://x.test/t', { method: 'POST' });
    const request = new Request('https://x.test/t', {
      method: 'POST',
      body: new Uint8Array([1, 2, 3]),
    });
    const accepted = await new XhttpTransport().accept(request, rctx);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;

    // 流式响应：身份头 + octet-stream
    const resp = accepted.respond();
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toBe('application/octet-stream');
    expect(resp.headers.get('X-Accel-Buffering')).toBe('no');
    const identityValue = resp.headers.get(identityHeader);
    expect(identityValue).toContain('https://x.invalid');
    expect(identityValue).toContain('_'); // identityKey

    // 上行 body 透传
    const reader = accepted.session.readable.getReader();
    const { value } = await reader.read();
    expect([...value!]).toEqual([1, 2, 3]);

    // 短路响应（测速 / UDP 拒绝）
    const local = accepted.respond({ localBody: 'UDP is not supported', status: 400 });
    expect(local.status).toBe(400);
    expect(await local.text()).toBe('UDP is not supported');
    expect(local.headers.get(identityHeader)).toBeNull(); // 短路响应不带身份头（原 L628-641）
    accepted.session.close();
  });
});
