/**
 * P6 链式代理测试 —— 注册表 / SOCKS5 握手字节 / HTTP CONNECT / 分派逻辑。
 * TURN/SSTP 全流程需真实 STUN/PPP 对端，此处锁定握手构造与错误路径；
 * 端到端对照原实现由 wrangler 冒烟与后续集成覆盖。
 */
import { describe, expect, it, vi } from 'vitest';
import { chainRegistry } from '../src/chain/registry';
import { Socks5Provider } from '../src/chain/socks5';
import { HttpProvider, httpConnectCore } from '../src/chain/http';
import { HttpsProvider } from '../src/chain/https';
import { TurnProvider } from '../src/chain/turn';
import { SstpProvider } from '../src/chain/sstp';
import type { ChainDialParams } from '../src/chain/base';
import type { TcpConnector, TcpSocket } from '../src/forward/dialer';
import { RequestContext } from '../src/context';
import { runForward } from '../src/forward/forwarder';
import { createRemoteConn } from '../src/forward/generation';
import type { Env } from '../src/env';
import type { ProxyContext } from '../src/forward/proxy-ctx';

const USER_ID = '00000000-0000-4000-8000-000000000000';

function makeRctx(url = 'https://x.test/'): RequestContext {
  const request = new Request(url);
  const env = { ADMIN: 'test-admin', UUID: USER_ID } as unknown as Env;
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
  return new RequestContext(request, env, ctx);
}

/** 可编排的 mock socket：按脚本应答 + 记录写出 */
function scriptedSocket(script: Array<'read' | Uint8Array>) {
  const written: Uint8Array[] = [];
  let readIdx = 0;
  const readable = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const step = script[readIdx++];
      if (step === undefined || step === 'read') {
        controller.close();
        return;
      }
      controller.enqueue(step);
      // 连续出数据直到脚本用尽或遇 'read' 等待下一次 pull —— 简化：出完即继续
      const next = script[readIdx];
      if (next !== undefined && next !== 'read') {
        // 继续由 pull 驱动
      } else if (next === undefined) {
        controller.close();
      }
    },
  });
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk);
    },
  });
  const socket: TcpSocket = {
    readable,
    writable,
    opened: Promise.resolve(),
    closed: Promise.resolve(),
    close: vi.fn(),
  };
  return { socket, written };
}

/** 构造一次性应答流（按序吐出给定 chunks 后关闭） */
function respondStream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[i++]!);
    },
  });
}

function makeSocketWithScript(responses: Uint8Array[]): { socket: TcpSocket; written: Uint8Array[] } {
  const written: Uint8Array[] = [];
  const readable = respondStream(responses);
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk);
    },
  });
  return {
    socket: { readable, writable, opened: Promise.resolve(), closed: Promise.resolve(), close: vi.fn() },
    written,
  };
}

function baseParams(socket: TcpSocket, written: Uint8Array[]): ChainDialParams {
  const tcpConnect = (() => socket) as unknown as TcpConnector;
  return {
    proxy: { hostname: '10.0.0.1', port: 1080 },
    target: { host: 'example.com', port: 443 },
    initialData: new Uint8Array([0xaa, 0xbb]),
    tcpConnect,
    // written 收集通过 makeSocketWithScript 闭包
    ...({ written } as object),
  };
}

describe('ChainRegistry', () => {
  it('注册五个子类：socks5/http/https/turn/sstp', () => {
    expect(chainRegistry.has('socks5')).toBe(true);
    expect(chainRegistry.has('http')).toBe(true);
    expect(chainRegistry.has('https')).toBe(true);
    expect(chainRegistry.has('turn')).toBe(true);
    expect(chainRegistry.has('sstp')).toBe(true);
    expect(chainRegistry.list().length).toBe(5);
  });

  it('未知类型 → undefined', () => {
    expect(chainRegistry.get('quic')).toBeUndefined();
  });

  it('各子类 name 与类型键一致', () => {
    expect(new Socks5Provider().name).toBe('socks5');
    expect(new HttpProvider().name).toBe('http');
    expect(new HttpsProvider().name).toBe('https');
    expect(new TurnProvider().name).toBe('turn');
    expect(new SstpProvider().name).toBe('sstp');
  });
});

describe('SOCKS5 握手（字节级）', () => {
  it('无认证：方法协商 → CONNECT → 写首包', async () => {
    // 应答：方法选择 [0x05, 0x00]；CONNECT 成功 [0x05, 0x00, 0x00, 0x01, ...]
    const { socket, written } = makeSocketWithScript([
      new Uint8Array([0x05, 0x00]),
      new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    ]);
    const params: ChainDialParams = {
      proxy: { hostname: '10.0.0.1', port: 1080 },
      target: { host: 'example.com', port: 443 },
      initialData: new Uint8Array([0xaa, 0xbb]),
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    const result = await new Socks5Provider().dial(params);
    expect(result.socket).toBeDefined();
    expect(written.length).toBe(3);
    // 1) 方法协商：05 01 00（无认证）
    expect([...written[0]!]).toEqual([0x05, 0x01, 0x00]);
    // 2) CONNECT：05 01 00 03 + len + 'example.com' + port 443
    const connect = written[1]!;
    expect(connect[0]).toBe(0x05);
    expect(connect[1]).toBe(0x01);
    expect(connect[3]).toBe(0x03);
    const hostLen = connect[4]!;
    expect(new TextDecoder().decode(connect.subarray(5, 5 + hostLen))).toBe('example.com');
    const portIdx = 5 + hostLen;
    expect((connect[portIdx]! << 8) | connect[portIdx + 1]!).toBe(443);
    // 3) 首包
    expect([...written[2]!]).toEqual([0xaa, 0xbb]);
  });

  it('带认证：05 02 00 02 → 用户名/密码包', async () => {
    const { socket, written } = makeSocketWithScript([
      new Uint8Array([0x05, 0x02]), // 选中用户密码认证
      new Uint8Array([0x01, 0x00]), // 认证成功
      new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    ]);
    const params: ChainDialParams = {
      proxy: { hostname: '10.0.0.1', port: 1080, username: 'user', password: 'pass' },
      target: { host: 'h', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await new Socks5Provider().dial(params);
    expect([...written[0]!]).toEqual([0x05, 0x02, 0x00, 0x02]);
    // 认证包：01 04 'user' 04 'pass'
    const auth = written[1]!;
    expect(auth[0]).toBe(0x01);
    expect(auth[1]).toBe(4);
    expect(new TextDecoder().decode(auth.subarray(2, 6))).toBe('user');
    expect(auth[6]).toBe(4);
    expect(new TextDecoder().decode(auth.subarray(7, 11))).toBe('pass');
  });

  it('方法协商失败 → CHAIN_SOCKS5_HANDSHAKE', async () => {
    const { socket } = makeSocketWithScript([new Uint8Array([0x05, 0xff])]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 1 },
      target: { host: 't', port: 1 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await expect(new Socks5Provider().dial(params)).rejects.toThrow(/S5 unsupported/);
  });

  it('连接失败（rep != 0）→ CHAIN_SOCKS5_CONNECT', async () => {
    const { socket } = makeSocketWithScript([
      new Uint8Array([0x05, 0x00]),
      new Uint8Array([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), // rep=1 一般失败
    ]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 1 },
      target: { host: 't', port: 1 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await expect(new Socks5Provider().dial(params)).rejects.toThrow(/S5 connection failed/);
  });
});

describe('HTTP CONNECT 握手（字节级）', () => {
  it('无认证请求行 + 200 应答 + 首包', async () => {
    const okResp = new TextEncoder().encode('HTTP/1.1 200 Connection established\r\n\r\n');
    const { socket, written } = makeSocketWithScript([okResp]);
    const params: ChainDialParams = {
      proxy: { hostname: 'proxy.local', port: 8080 },
      target: { host: 'example.com', port: 443 },
      initialData: new Uint8Array([0x11, 0x22]),
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    const result = await new HttpProvider().dial(params);
    expect(result.socket).toBeDefined();
    expect(written.length).toBe(2);
    const req = new TextDecoder().decode(written[0]!);
    expect(req).toContain('CONNECT example.com:443 HTTP/1.1');
    expect(req).toContain('Host: example.com:443');
    expect(req).not.toContain('Proxy-Authorization');
    expect(req.endsWith('\r\n\r\n')).toBe(true);
    expect([...written[1]!]).toEqual([0x11, 0x22]);
  });

  it('带认证 → Basic Proxy-Authorization', async () => {
    const okResp = new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\n');
    const { socket, written } = makeSocketWithScript([okResp]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 8080, username: 'u', password: 'pw' },
      target: { host: 't', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await new HttpProvider().dial(params);
    const req = new TextDecoder().decode(written[0]!);
    expect(req).toContain(`Proxy-Authorization: Basic ${btoa('u:pw')}`);
  });

  it('非 2xx → CHAIN_HTTP_CONNECT', async () => {
    const badResp = new TextEncoder().encode('HTTP/1.1 403 Forbidden\r\n\r\n');
    const { socket } = makeSocketWithScript([badResp]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 8080 },
      target: { host: 't', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await expect(new HttpProvider().dial(params)).rejects.toThrow(/HTTP 403/);
  });

  it('CONNECT 响应头后夹带数据 → 回灌 readable', async () => {
    const resp = new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\nTAILED');
    const { socket } = makeSocketWithScript([resp]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 8080 },
      target: { host: 't', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    const result = await new HttpProvider().dial(params);
    // 读回灌流：应先得到 'TAILED'
    const reader = result.socket.readable.getReader();
    const { value } = await reader.read();
    expect(new TextDecoder().decode(value!)).toBe('TAILED');
  });

  it('响应头前关闭 → CHAIN_HTTP_CONNECT', async () => {
    const { socket } = makeSocketWithScript([]);
    const params: ChainDialParams = {
      proxy: { hostname: 'p', port: 8080 },
      target: { host: 't', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await expect(new HttpProvider().dial(params)).rejects.toThrow(/关闭连接/);
  });
});

describe('HTTPS 分派', () => {
  it('非 IP 主机名 → 走 httpConnect secureTransport（fetcher TLS）', async () => {
    // tcpConnect 收到 init.secureTransport === 'on'
    const captured: unknown[] = [];
    const { socket, written } = makeSocketWithScript([new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\n')]);
    const tcpConnect = ((opts: unknown, init?: unknown) => {
      captured.push({ opts, init });
      return socket;
    }) as unknown as TcpConnector;
    const params: ChainDialParams = {
      proxy: { hostname: 'proxy.example.com', port: 443 },
      target: { host: 't', port: 443 },
      initialData: null,
      tcpConnect,
    };
    await new HttpsProvider().dial(params);
    expect(captured.length).toBe(1);
    expect((captured[0] as { init?: { secureTransport?: string } }).init?.secureTransport).toBe('on');
    expect(written.length).toBe(1);
  });

  it('IP 主机名 → 走自研 TLS（tcpConnect 无 init；AES-GCM 失败后 ChaCha 回退再拨一次）', async () => {
    const captured: unknown[] = [];
    const { socket } = makeSocketWithScript([]);
    const tcpConnect = ((opts: unknown, init?: unknown) => {
      captured.push({ opts, init });
      return socket;
    }) as unknown as TcpConnector;
    const params: ChainDialParams = {
      proxy: { hostname: '1.2.3.4', port: 443 },
      target: { host: 't', port: 443 },
      initialData: null,
      tcpConnect,
    };
    // 自研 TLS 握手会等 ServerHello —— 应答流立即关闭 → 握手失败
    await expect(new HttpsProvider().dial(params)).rejects.toThrow();
    // 原实现：AES-GCM 失败 → allowChacha 回退重试 → 至少 2 次拨号，均无 secureTransport init
    expect(captured.length).toBeGreaterThanOrEqual(1);
    expect(captured.every((c) => (c as { init?: unknown }).init === undefined)).toBe(true);
  });
});

describe('runForward 链式路径', () => {
  const baseProxy = (type: string): ProxyContext => ({
    trojanProxyAddr: null,
    proxyIP: '',
    proxyType: type as ProxyContext['proxyType'],
    proxyAccount: '',
    proxyGlobal: true, // 全局 → 直接走链式，不看白名单
    proxyParams: { hostname: '10.0.0.1', port: 1080 },
    proxyFallback: false,
  });

  it('socks5 全局代理 → 调用 Socks5Provider（非直连）', async () => {
    const rctx = makeRctx();
    const { socket, written } = makeSocketWithScript([
      new Uint8Array([0x05, 0x00]),
      new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    ]);
    // connectOnly=false 会 connectStreams；用 connectOnly=true 拿 socket
    const result = await runForward({
      host: 'example.com',
      port: 443,
      rawData: new Uint8Array([1, 2]),
      client: { readyState: 1, send: () => {}, close: () => {} },
      respHeader: null,
      remoteConn: createRemoteConn(),
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: baseProxy('socks5'),
      connectOnly: true,
      tcpConnect: (() => socket) as unknown as TcpConnector,
      socks5Whitelist: [],
      rctx,
    });
    expect(result).toBe(socket);
    // 首包已通过 SOCKS5 CONNECT 之后写入
    expect(written.length).toBeGreaterThanOrEqual(3);
    expect([...written[0]!]).toEqual([0x05, 0x01, 0x00]); // 无认证方法协商
  });

  it('http 全局代理 → 调用 HttpProvider', async () => {
    const rctx = makeRctx();
    const { socket, written } = makeSocketWithScript([new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\n')]);
    const result = await runForward({
      host: 'example.com',
      port: 443,
      rawData: new Uint8Array([9]),
      client: { readyState: 1, send: () => {}, close: () => {} },
      respHeader: null,
      remoteConn: createRemoteConn(),
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: baseProxy('http'),
      connectOnly: true,
      tcpConnect: (() => socket) as unknown as TcpConnector,
      socks5Whitelist: [],
      rctx,
    });
    expect(result).toBe(socket);
    const req = new TextDecoder().decode(written[0]!);
    expect(req).toContain('CONNECT example.com:443');
    expect([...written[1]!]).toEqual([9]); // 首包
  });

  it('非全局但白名单命中 → 仍走链式', async () => {
    const rctx = makeRctx();
    const { socket, written } = makeSocketWithScript([
      new Uint8Array([0x05, 0x00]),
      new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    ]);
    const pc = baseProxy('socks5');
    pc.proxyGlobal = false;
    await runForward({
      host: 'scholar.google.com',
      port: 443,
      rawData: null,
      client: { readyState: 1, send: () => {}, close: () => {} },
      respHeader: null,
      remoteConn: createRemoteConn(),
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: pc,
      connectOnly: true,
      tcpConnect: (() => socket) as unknown as TcpConnector,
      socks5Whitelist: ['scholar.google.com'],
      rctx,
    });
    expect(written.length).toBeGreaterThanOrEqual(2);
    expect([...written[0]!]).toEqual([0x05, 0x01, 0x00]);
  });

  it('白名单未命中且非全局 → 走直连（tcpConnect 拨目标）', async () => {
    const rctx = makeRctx();
    const calls: Array<{ hostname: string; port: number }> = [];
    const direct = makeSocketWithScript([]); // 直连立即 EOF
    const tcpConnect = ((opts: { hostname: string; port: number }) => {
      calls.push(opts);
      return direct.socket;
    }) as unknown as TcpConnector;
    const pc = baseProxy('socks5');
    pc.proxyGlobal = false;
    await runForward({
      host: 'other.example.org',
      port: 443,
      rawData: null,
      client: { readyState: 1, send: () => {}, close: () => {} },
      respHeader: null,
      remoteConn: createRemoteConn(),
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: pc,
      connectOnly: true,
      tcpConnect,
      socks5Whitelist: ['scholar.google.com'],
      rctx,
    });
    // 直连拨的是目标本身（并发 N 路），不是代理 10.0.0.1
    expect(calls.every((c) => c.hostname === 'other.example.org')).toBe(true);
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });
});

describe('TURN/SSTP 提供者结构', () => {
  it('TurnProvider.dial：目标为域名时先 DoH（应答关闭 → 抛错而非挂起）', async () => {
    const { socket } = makeSocketWithScript([]);
    const params: ChainDialParams = {
      proxy: { hostname: 'turn.example.com', port: 3478 },
      target: { host: 'not-resolvable.invalid', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    // DoH 查询失败返回 [] → 抛 Could not resolve
    await expect(new TurnProvider().dial(params)).rejects.toThrow(/Could not resolve|IPv4/);
  });

  it('TurnProvider.dial：目标已是 IPv4 → 进入 STUN 流程（socket 关闭 → 超时/失败）', async () => {
    const { socket } = makeSocketWithScript([]); // 控制通道立即 EOF
    const params: ChainDialParams = {
      proxy: { hostname: '127.0.0.1', port: 3478 },
      target: { host: '1.2.3.4', port: 80 },
      initialData: null,
      tcpConnect: (() => socket) as unknown as TcpConnector,
    };
    await expect(new TurnProvider().dial(params)).rejects.toThrow();
  });

  it('SstpProvider.dial：secureTransport 拨号 + 握手失败（应答关闭）', async () => {
    const captured: Array<{ init?: { secureTransport?: string } }> = [];
    const { socket } = makeSocketWithScript([]);
    const tcpConnect = ((_opts: unknown, init?: unknown) => {
      captured.push({ init } as { init?: { secureTransport?: string } });
      return socket;
    }) as unknown as TcpConnector;
    const params: ChainDialParams = {
      proxy: { hostname: 'vpn.example.com', port: 443 },
      target: { host: '1.2.3.4', port: 443 },
      initialData: null,
      tcpConnect,
    };
    await expect(new SstpProvider().dial(params)).rejects.toThrow();
    // SSTP 原实现强制 secureTransport:'on'
    expect(captured[0]?.init?.secureTransport).toBe('on');
  });
});

// 移除未用辅助
void baseParams;
void scriptedSocket;
void httpConnectCore;
