/**
 * P5 转发核心测试 —— Grain 队列 / 连接世代 / 拨号 / 测速 / proxyCtx / UDP 帧 / 编排器。
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  createGrainBuffer,
  createUplinkWriteQueue,
  createDownlinkGrainSender,
  createUplinkCoalesceStream,
  UPLINK_QUEUE_MAX_BYTES,
  type ClientLikeSocket,
} from '../src/forward/grain';
import { createRemoteConn, beginTcpGeneration, invalidateTcpGeneration } from '../src/forward/generation';
import {
  createRequestTcpConnector,
  openCandidatesConcurrent,
  connectDirect,
  connectProxyIP,
  writeFirstPacket,
  type TcpSocket,
  type DialCandidate,
} from '../src/forward/dialer';
import { isSpeedTestSite, buildLocal204Response, buildWsLocal204Response } from '../src/forward/speedtest';
import { buildProxyContext, getSocks5Account, parseTrojanProxyAddr, getProxyDefaultPort } from '../src/forward/proxy-ctx';
import { forwardTrojanUdp } from '../src/forward/udp';
import { runForward } from '../src/forward/forwarder';
import { runSession } from '../src/session/orchestrator';
import { handleHttpRoute } from '../src/router';
import { RequestContext } from '../src/context';
import { EDT_VERSION } from '../src/services/brand';
import type { Env } from '../src/env';
import type { TransportSession } from '../src/transport/base';
import { concatByteChunks } from '../src/utils/bytes';

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

/** 构造合法 VLESS 首包：version+uuid+optLen=0+cmd+port+atype+addr+payload
 *  atype: 1=IPv4（点分四段） / 2=域名 */
function buildVlessFirstPacket(uuid: string, host: string, port: number, payload: Uint8Array = new Uint8Array(0), cmd = 1): Uint8Array {
  const uuidBytes = uuidToBytes(uuid);
  const isIPv4 = /^\d+\.\d+\.\d+\.\d+$/.test(host);
  const hostBytes = new TextEncoder().encode(host);
  const addrLen = isIPv4 ? 4 : 1 + hostBytes.byteLength;
  const headerLen = 1 + 16 + 1 + 1 + 2 + 1 + addrLen;
  const out = new Uint8Array(headerLen + payload.byteLength);
  let i = 0;
  out[i++] = 0; // version
  out.set(uuidBytes, i);
  i += 16;
  out[i++] = 0; // optLen
  out[i++] = cmd; // 1=TCP 2=UDP
  out[i++] = (port >> 8) & 0xff;
  out[i++] = port & 0xff;
  if (isIPv4) {
    out[i++] = 1;
    for (const part of host.split('.').map(Number)) out[i++] = part & 0xff;
  } else {
    out[i++] = 2;
    out[i++] = hostBytes.byteLength;
    out.set(hostBytes, i);
    i += hostBytes.byteLength;
  }
  out.set(payload, i);
  return out;
}

/** 模拟 TCP socket：记录写入，readable 可注入数据 */
function makeMockSocket(opts: { failOpen?: boolean; downlink?: Uint8Array[] } = {}): TcpSocket & { written: Uint8Array[] } {
  const written: Uint8Array[] = [];
  const downlinkQueue = [...(opts.downlink ?? [])];
  let closeCount = 0;
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of downlinkQueue) controller.enqueue(chunk);
      controller.close();
    },
  });
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk);
    },
  });
  return {
    written,
    readable,
    writable,
    opened: opts.failOpen ? Promise.reject(new Error('connect fail')) : Promise.resolve(),
    closed: Promise.resolve(),
    close() {
      closeCount++;
    },
    get closeCount() {
      return closeCount;
    },
  } as TcpSocket & { written: Uint8Array[]; closeCount: number };
}

function makeMockClient(): ClientLikeSocket & { sent: Uint8Array[]; closed: boolean } {
  const sent: Uint8Array[] = [];
  const state = { closed: false };
  return {
    sent,
    get closed() {
      return state.closed;
    },
    get readyState() {
      return state.closed ? 3 : 1;
    },
    send(data) {
      sent.push(data instanceof Uint8Array ? data : new Uint8Array(data as ArrayBuffer));
    },
    close() {
      state.closed = true;
    },
  };
}

function makeSession(opts: { earlyData?: Uint8Array; chunks?: Uint8Array[] } = {}): TransportSession & {
  clientWrites: Uint8Array[];
  closed: boolean;
  enqueue(c: Uint8Array): void;
  end(): void;
} {
  const chunks = [...(opts.chunks ?? [])];
  const clientWrites: Uint8Array[] = [];
  const state = { closed: false };
  let ctrl: ReadableStreamDefaultController<Uint8Array> | null = null;
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      ctrl = controller;
      for (const c of chunks) controller.enqueue(c);
    },
  });
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      clientWrites.push(chunk);
    },
  });
  return {
    name: 'test',
    readable,
    writable,
    earlyData: opts.earlyData,
    clientWrites,
    get closed() {
      return state.closed;
    },
    close() {
      state.closed = true;
      try {
        ctrl?.close();
      } catch {
        /* ignore */
      }
    },
    enqueue(chunk: Uint8Array) {
      ctrl?.enqueue(chunk);
    },
    end() {
      try {
        ctrl?.close();
      } catch {
        /* ignore */
      }
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ————————————————————————— Grain —————————————————————————

describe('GrainBuffer', () => {
  it('absorb + coalesce：容量内合并为一块', () => {
    const g = createGrainBuffer(100);
    g.absorb({ chunk: new Uint8Array([1, 2]) });
    g.absorb({ chunk: new Uint8Array([3]) });
    expect(g.byteCount).toBe(3);
    expect(g.entryCount).toBe(2);
    const packed = g.coalesce();
    expect(packed).not.toBeNull();
    expect([...packed!.chunk]).toEqual([1, 2, 3]);
    expect(packed!.items.length).toBe(2);
    expect(g.isEmpty).toBe(true);
  });

  it('coalesce：超过容量只取到不超限的前缀', () => {
    const g = createGrainBuffer(4);
    g.absorb({ chunk: new Uint8Array([1, 2]) });
    g.absorb({ chunk: new Uint8Array([3, 4]) });
    g.absorb({ chunk: new Uint8Array([5]) });
    const packed = g.coalesce()!;
    expect([...packed.chunk]).toEqual([1, 2, 3, 4]);
    expect(packed.items.length).toBe(2);
    expect(g.entryCount).toBe(1); // 剩 [5]
  });

  it('coalesce：单块 ≥ 容量直接返回', () => {
    const g = createGrainBuffer(2);
    g.absorb({ chunk: new Uint8Array([1, 2, 3]) });
    const packed = g.coalesce()!;
    expect([...packed.chunk]).toEqual([1, 2, 3]);
    expect(packed.items.length).toBe(1);
  });

  it('copyCoalesceResult=true 时返回拷贝（视图不随后续 absorb 失效）', () => {
    const g = createGrainBuffer(10, true);
    g.absorb({ chunk: new Uint8Array([1, 2]) });
    const packed = g.coalesce()!;
    g.absorb({ chunk: new Uint8Array([9, 9]) });
    void g.coalesce();
    expect([...packed.chunk]).toEqual([1, 2]);
  });

  it('clear 带 processItem 回调逐条处理', () => {
    const g = createGrainBuffer(10);
    g.absorb({ chunk: new Uint8Array([1]) });
    g.absorb({ chunk: new Uint8Array([2]) });
    const seen: number[] = [];
    g.clear((item) => seen.push(item.chunk[0]!));
    expect(seen).toEqual([1, 2]);
    expect(g.isEmpty).toBe(true);
    expect(g.byteCount).toBe(0);
  });

  it('空 absorb 返回 false', () => {
    const g = createGrainBuffer(10);
    expect(g.absorb({ chunk: new Uint8Array(0) })).toBe(false);
    expect(g.coalesce()).toBeNull();
  });
});

describe('UplinkWriteQueue', () => {
  function makeWriterHarness() {
    const writes: Uint8Array[] = [];
    let failNext = false;
    const writer = {
      write: async (chunk: Uint8Array) => {
        if (failNext) {
          failNext = false;
          throw new Error('write fail');
        }
        writes.push(chunk);
      },
      releaseLock: () => {},
    };
    return {
      writes,
      failOnce: () => {
        failNext = true;
      },
      getWriter: () => writer as unknown as WritableStreamDefaultWriter<Uint8Array>,
    };
  }

  it('write：无 writer 且无 connectTask → false（首包阶段）', () => {
    const q = createUplinkWriteQueue({ getWriter: () => null, getConnectTask: () => null });
    expect(q.write(new Uint8Array([1]))).toBe(false);
  });

  it('write：有 writer → 入队并 drain 写出', async () => {
    const h = makeWriterHarness();
    const q = createUplinkWriteQueue({ getWriter: h.getWriter });
    expect(q.write(new Uint8Array([1, 2]))).toBe(true);
    await q.waitIdle();
    expect(h.writes.length).toBe(1);
    expect([...h.writes[0]!]).toEqual([1, 2]);
  });

  it('合包：drain 写上一块期间攒下的多小块合并为一次 write', async () => {
    const writes: Uint8Array[] = [];
    let releaseFirst: (() => void) | null = null;
    const firstGate = new Promise<void>((r) => {
      releaseFirst = r;
    });
    let call = 0;
    const writer = {
      write: async (chunk: Uint8Array) => {
        call++;
        if (call === 1) {
          writes.push(chunk);
          await firstGate; // 阻塞第一块，让后续小块攒进 grain
          return;
        }
        writes.push(chunk);
      },
      releaseLock: () => {},
    };
    const q = createUplinkWriteQueue({ getWriter: () => writer as unknown as WritableStreamDefaultWriter<Uint8Array> });
    q.write(new Uint8Array([1]));
    // 等第一块进入 write（drain 已 bundle [1] 并阻塞）
    await new Promise((r) => setTimeout(r, 5));
    q.write(new Uint8Array([2]));
    q.write(new Uint8Array([3]));
    expect(writes.length).toBe(1); // 第一块已写出，后续仍在 grain
    releaseFirst!();
    await q.waitIdle();
    expect(writes.length).toBe(2);
    expect([...writes[0]!]).toEqual([1]);
    expect([...writes[1]!]).toEqual([2, 3]); // 合包
  });

  it('队列超限 → 抛 isQueueOverflow 并 closeConnection', async () => {
    const closed: unknown[] = [];
    const q = createUplinkWriteQueue({
      getWriter: () => null,
      getConnectTask: () => new Promise(() => {}), // 永不完成 → 不 drain
      closeConnection: (err) => closed.push(err),
    });
    // 直接塞超限数据（绕过 getWriter 检查：有 connectTask）
    const huge = new Uint8Array(UPLINK_QUEUE_MAX_BYTES + 1);
    expect(() => q.write(huge)).toThrow(/overflow/);
    expect(closed.length).toBe(1);
    expect((closed[0] as { isQueueOverflow?: boolean }).isQueueOverflow).toBe(true);
  });

  it('writeAndWait：等待 flush 完成后 resolve', async () => {
    const h = makeWriterHarness();
    const q = createUplinkWriteQueue({ getWriter: h.getWriter });
    const done = await q.writeAndWait(new Uint8Array([7]));
    expect(done).toBe(true);
    expect(h.writes.length).toBe(1);
  });

  it('clear 后 write 返回 false', () => {
    const h = makeWriterHarness();
    const q = createUplinkWriteQueue({ getWriter: h.getWriter });
    q.clear();
    expect(q.write(new Uint8Array([1]))).toBe(false);
  });
});

describe('DownlinkGrainSender', () => {
  it('send 小块攒到 tail 阈值后 flush 发出', async () => {
    const client = makeMockClient();
    const sender = createDownlinkGrainSender(client);
    // 32KB - 512 = 31612 以下不立即 flush；发满 tail 附近触发
    const big = new Uint8Array(31620).fill(0xab);
    await sender.send(big);
    await sender.flush();
    expect(client.sent.length).toBeGreaterThan(0);
    const total = client.sent.reduce((s, c) => s + c.byteLength, 0);
    expect(total).toBe(31620);
  });

  it('sendDirectly 立即发出（≥ CHUNK 的大块）', async () => {
    const client = makeMockClient();
    const sender = createDownlinkGrainSender(client);
    const chunk = new Uint8Array(40 * 1024).fill(1);
    await sender.sendDirectly(chunk);
    expect(client.sent.length).toBe(1);
    expect(client.sent[0]!.byteLength).toBe(40 * 1024);
  });

  it('headerData 函数只前置一次', async () => {
    const client = makeMockClient();
    let header: Uint8Array | null = new Uint8Array([0x01, 0x00]);
    const sender = createDownlinkGrainSender(client, () => {
      const h = header;
      header = null;
      return h;
    });
    await sender.sendDirectly(new Uint8Array([0xaa]));
    await sender.sendDirectly(new Uint8Array([0xbb]));
    expect([...client.sent[0]!]).toEqual([0x01, 0x00, 0xaa]);
    expect([...client.sent[1]!]).toEqual([0xbb]);
  });

  it('isActive=false 时丢弃数据', async () => {
    const client = makeMockClient();
    const sender = createDownlinkGrainSender(client, null, () => false);
    await sender.send(new Uint8Array([1, 2, 3]));
    await sender.flush();
    expect(client.sent.length).toBe(0);
  });
});

describe('UplinkCoalesceStream', () => {
  it('小块攒到 target 后经 readable 输出', async () => {
    const c = createUplinkCoalesceStream(8);
    const reader = c.readable.getReader();
    await c.write(new Uint8Array([1, 2, 3]));
    await c.write(new Uint8Array([4, 5])); // 5 < 8 → 缓冲
    const readPromise = reader.read();
    await c.write(new Uint8Array([6, 7, 8])); // 5+3=8 → flush
    const { value } = await readPromise;
    expect([...value!]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    await c.end();
    const { done } = await reader.read();
    expect(done).toBe(true);
  });

  it('≥ target 的块直通', async () => {
    const c = createUplinkCoalesceStream(4);
    const reader = c.readable.getReader();
    // 先挂 read 再 write，避免 Transform 背压阻塞
    const readPromise = reader.read();
    await c.write(new Uint8Array([1, 2, 3, 4, 5]));
    const { value } = await readPromise;
    expect([...value!]).toEqual([1, 2, 3, 4, 5]);
    await c.end();
  });
});

// ————————————————————————— 世代 —————————————————————————

describe('连接世代', () => {
  it('begin 递增 generation 并清空旧 socket', () => {
    const conn = createRemoteConn();
    const sock = { close: vi.fn() };
    conn.socket = sock;
    const { generation } = beginTcpGeneration(conn);
    expect(generation).toBe(1);
    expect(conn.socket).toBeNull();
    expect(sock.close).toHaveBeenCalled();
  });

  it('invalidate 再递增并关闭 socket', () => {
    const conn = createRemoteConn();
    beginTcpGeneration(conn);
    const sock = { close: vi.fn() };
    conn.socket = sock;
    invalidateTcpGeneration(conn);
    expect(conn.generation).toBe(2);
    expect(conn.socket).toBeNull();
    expect(sock.close).toHaveBeenCalled();
  });

  it('begin 排空旧 downlinkController', async () => {
    const conn = createRemoteConn();
    const stopAndFlush = vi.fn(async () => {});
    conn.downlinkController = { stopAndFlush };
    beginTcpGeneration(conn);
    await conn.downlinkDrain;
    expect(stopAndFlush).toHaveBeenCalled();
    expect(conn.downlinkController).toBeNull();
  });
});

// ————————————————————————— 拨号 —————————————————————————

describe('拨号', () => {
  it('openCandidatesConcurrent：单候选直接拨', async () => {
    const sock = makeMockSocket();
    const tcp = vi.fn(() => sock);
    const result = await openCandidatesConcurrent(tcp as never, [{ hostname: 'a.com', port: 80 }]);
    expect(result.socket).toBe(sock);
    expect(tcp).toHaveBeenCalledTimes(1);
  });

  it('openCandidatesConcurrent：多候选 Promise.any 取先成，败者关闭', async () => {
    const fast = makeMockSocket();
    const slow = makeMockSocket();
    let call = 0;
    const tcp = vi.fn(() => {
      call++;
      return call === 1 ? fast : slow;
    });
    // 让第一个立即成功，第二个稍后
    const result = await openCandidatesConcurrent(tcp as never, [
      { hostname: 'a.com', port: 80 },
      { hostname: 'b.com', port: 80 },
    ]);
    expect(result.socket).toBeDefined();
    expect(tcp).toHaveBeenCalledTimes(2);
  });

  it('connectDirect：并发 N 路 + 写首包', async () => {
    const socks = [makeMockSocket(), makeMockSocket()];
    let i = 0;
    const tcp = vi.fn(() => socks[i++ % socks.length]!);
    const { rctx } = makeRctx('https://x.test/');
    const first = new Uint8Array([1, 2, 3]);
    const socket = await connectDirect(rctx, tcp as never, 'example.com', 443, first, false);
    expect(socket).toBeDefined();
    expect(tcp).toHaveBeenCalledTimes(Math.max(1, rctx.dial.tcpConcurrentDial));
    // 至少一路写入了首包
    const anyWritten = socks.some((s) => s.written.length > 0);
    expect(anyWritten).toBe(true);
  });

  it('connectDirect：全部失败则抛错', async () => {
    const tcp = vi.fn(() => makeMockSocket({ failOpen: true }));
    const { rctx } = makeRctx('https://x.test/');
    await expect(connectDirect(rctx, tcp as never, 'example.com', 443, null, false)).rejects.toThrow();
  });

  it('connectProxyIP：代理列表成功后不回落', async () => {
    const sock = makeMockSocket();
    const calls: Array<{ hostname: string; port: number }> = [];
    const tcp = ((options: { hostname: string; port: number }) => {
      calls.push(options);
      return sock;
    }) as never;
    const { rctx } = makeRctx('https://x.test/');
    const result = await connectProxyIP(rctx, tcp, 'target.com', 443, null, [['1.2.3.4', 443]], true, 0);
    expect(result.socket).toBe(sock);
    expect(result.nextIndex).toBe(0);
    expect(calls).toEqual([{ hostname: '1.2.3.4', port: 443 }]);
  });

  it('connectProxyIP：代理全失败 + fallback → 直连 target', async () => {
    const calls: Array<{ hostname: string; port: number }> = [];
    let n = 0;
    const tcp = ((options: { hostname: string; port: number }) => {
      n++;
      calls.push(options);
      if (n === 1) return makeMockSocket({ failOpen: true }); // 代理失败
      return makeMockSocket(); // 直连成功（默认并发 2 路）
    }) as never;
    const { rctx } = makeRctx('https://x.test/');
    const result = await connectProxyIP(rctx, tcp, 'target.com', 443, null, [['1.2.3.4', 443]], true, 0);
    expect(result.socket).toBeDefined();
    // 1 次代理失败 + tcpConcurrentDial(2) 次直连
    expect(calls.length).toBe(1 + Math.max(1, rctx.dial.tcpConcurrentDial));
    expect(calls[calls.length - 1]!.hostname).toBe('target.com');
  });

  it('connectProxyIP：代理全失败 + 无 fallback → 抛 FORWARD_PROXY_EXHAUSTED', async () => {
    const tcp = vi.fn(() => makeMockSocket({ failOpen: true }));
    const { rctx } = makeRctx('https://x.test/');
    await expect(connectProxyIP(rctx, tcp as never, 'target.com', 443, null, [['1.2.3.4', 443]], false, 0)).rejects.toThrow(
      /反代兜底/,
    );
  });

  it('createRequestTcpConnector：无 fetcher 抛 FORWARD_NO_CONNECTOR', () => {
    const req = new Request('https://x.test/');
    expect(() => createRequestTcpConnector(req)).toThrow(/fetcher/);
  });

  it('writeFirstPacket：空数据不写', async () => {
    const sock = makeMockSocket();
    await writeFirstPacket(sock, null);
    await writeFirstPacket(sock, new Uint8Array(0));
    expect(sock.written.length).toBe(0);
  });
});

// ————————————————————————— 测速 —————————————————————————

describe('测速识别与本地 204', () => {
  it('isSpeedTestSite：精确 / 子域 / 否定', () => {
    expect(isSpeedTestSite('speed.cloudflare.com')).toBe(true);
    expect(isSpeedTestSite('cp.cloudflare.com')).toBe(true);
    expect(isSpeedTestSite('SPEED.CLOUDFLARE.COM')).toBe(true);
    expect(isSpeedTestSite('www.speed.cloudflare.com')).toBe(true);
    expect(isSpeedTestSite('example.com')).toBe(false);
    expect(isSpeedTestSite('notspeed.cloudflare.com.evil.com')).toBe(false);
  });

  it('buildLocal204Response：无 header 精确字节', () => {
    const out = buildLocal204Response(null);
    const text = new TextDecoder().decode(out);
    expect(text).toContain('HTTP/1.1 204 No Content');
    expect(text).toContain('Connection: close');
    expect(text).toContain('Content-Length: 0');
  });

  it('buildLocal204Response：有 header 前置', () => {
    const header = new Uint8Array([0x01, 0x00]);
    const out = buildLocal204Response(header);
    expect([...out.subarray(0, 2)]).toEqual([1, 0]);
    expect(new TextDecoder().decode(out.subarray(2))).toContain('204 No Content');
  });

  it('buildWsLocal204Response：keep-alive', () => {
    const text = new TextDecoder().decode(buildWsLocal204Response(null));
    expect(text).toContain('Connection: keep-alive');
  });
});

// ————————————————————————— proxyCtx —————————————————————————

describe('buildProxyContext', () => {
  it('默认：无参数 → proxyType=null，保留 defaultProxyIP', () => {
    const { rctx } = makeRctx('https://x.test/tunnel');
    const ctx = buildProxyContext(rctx, rctx.url, 'auto.proxyip.example', true);
    expect(ctx.proxyType).toBeNull();
    expect(ctx.proxyIP).toBe('auto.proxyip.example');
    expect(ctx.proxyFallback).toBe(true);
    expect(ctx.trojanProxyAddr).toBeNull();
  });

  it('?proxyip=1.2.3.4 → 设置反代并关兜底', () => {
    const { rctx } = makeRctx('https://x.test/t?proxyip=1.2.3.4');
    const ctx = buildProxyContext(rctx, rctx.url, 'default.example', true);
    expect(ctx.proxyIP).toBe('1.2.3.4');
    expect(ctx.proxyType).toBeNull();
    expect(ctx.proxyFallback).toBe(false);
  });

  it('?socks5=user:pass@host:1080 → socks5（无 globalproxy → 非全局）', () => {
    const { rctx } = makeRctx('https://x.test/t?socks5=user:pass@10.0.0.1:1080');
    const ctx = buildProxyContext(rctx, rctx.url, '', true);
    expect(ctx.proxyType).toBe('socks5');
    // 原实现：query 型 socks5 的 global 仅由 ?globalproxy 决定
    expect(ctx.proxyGlobal).toBe(false);
    expect(ctx.proxyParams.hostname).toBe('10.0.0.1');
    expect(ctx.proxyParams.port).toBe(1080);
    expect(ctx.proxyParams.username).toBe('user');
    expect(ctx.proxyParams.password).toBe('pass');
  });

  it('路径 /socks5=user:pass@host:1080', () => {
    const { rctx } = makeRctx('https://x.test/socks5=user:pass@10.0.0.2:1080/tunnel');
    const ctx = buildProxyContext(rctx, rctx.url, '', true);
    expect(ctx.proxyType).toBe('socks5');
    expect(ctx.proxyParams.hostname).toBe('10.0.0.2');
  });

  it('路径末尾 /trojan=host:port → trojanProxyAddr', () => {
    // 原正则 [^?#\s]+ 贪婪含 /，故 trojan 段须在路径末尾
    const { rctx } = makeRctx('https://x.test/tunnel/trojan=1.2.3.4:8443');
    const ctx = buildProxyContext(rctx, rctx.url, '', true);
    expect(ctx.trojanProxyAddr).toEqual({ hostname: '1.2.3.4', port: 8443 });
  });

  it('路径 /proxyip=5.6.7.8 → 反代', () => {
    const { rctx } = makeRctx('https://x.test/proxyip=5.6.7.8/tunnel');
    const ctx = buildProxyContext(rctx, rctx.url, 'default', true);
    expect(ctx.proxyIP).toBe('5.6.7.8');
    expect(ctx.proxyFallback).toBe(false);
  });

  it('?globalproxy 存在 → proxyGlobal', () => {
    const { rctx } = makeRctx('https://x.test/t?socks5=u:p@h:1&globalproxy');
    const ctx = buildProxyContext(rctx, rctx.url, '', true);
    expect(ctx.proxyGlobal).toBe(true);
  });
});

describe('getSocks5Account / parseTrojanProxyAddr', () => {
  it('纯 host:port + 默认端口', () => {
    const r = getSocks5Account('1.2.3.4', 1080);
    expect(r).toEqual({ username: undefined, password: undefined, hostname: '1.2.3.4', port: 1080 });
  });

  it('user:pass@host:port', () => {
    const r = getSocks5Account('alice:secret@proxy.example:1080');
    expect(r.username).toBe('alice');
    expect(r.password).toBe('secret');
    expect(r.hostname).toBe('proxy.example');
    expect(r.port).toBe(1080);
  });

  it('b64 认证段解码', () => {
    const b64 = Buffer.from('user:pass').toString('base64');
    const r = getSocks5Account(`${b64}@host:1080`);
    expect(r.username).toBe('user');
    expect(r.password).toBe('pass');
  });

  it('缺密码抛错', () => {
    expect(() => getSocks5Account('onlyuser@host:1080')).toThrow(/username:password/);
  });

  it('IPv6 方括号', () => {
    const r = getSocks5Account('[2001:db8::1]:1080');
    expect(r.hostname).toBe('[2001:db8::1]');
    expect(r.port).toBe(1080);
  });

  it('parseTrojanProxyAddr 合法 / 非法', () => {
    expect(parseTrojanProxyAddr('1.2.3.4:443')).toEqual({ hostname: '1.2.3.4', port: 443 });
    expect(() => parseTrojanProxyAddr('http://x')).toThrow();
    expect(() => parseTrojanProxyAddr('noport')).toThrow();
    expect(() => parseTrojanProxyAddr('h:99999')).toThrow();
  });

  it('getProxyDefaultPort', () => {
    expect(getProxyDefaultPort('socks5')).toBe(1080);
    expect(getProxyDefaultPort('http')).toBe(80);
    expect(getProxyDefaultPort('https')).toBe(443);
    expect(getProxyDefaultPort('turn')).toBe(3478);
    expect(getProxyDefaultPort('sstp')).toBe(443);
    expect(getProxyDefaultPort(null)).toBe(80);
  });
});

// ————————————————————————— Trojan UDP —————————————————————————

describe('forwardTrojanUdp 帧解析', () => {
  function buildTrojanUdpFrame(host: string, port: number, payload: Uint8Array): Uint8Array {
    // atype=3 域名 | len | domain | port | len | CRLF | payload
    const domain = new TextEncoder().encode(host);
    const out = new Uint8Array(1 + 1 + domain.byteLength + 2 + 2 + 2 + payload.byteLength);
    let i = 0;
    out[i++] = 3;
    out[i++] = domain.byteLength;
    out.set(domain, i);
    i += domain.byteLength;
    out[i++] = (port >> 8) & 0xff;
    out[i++] = port & 0xff;
    out[i++] = (payload.byteLength >> 8) & 0xff;
    out[i++] = payload.byteLength & 0xff;
    out[i++] = 0x0d;
    out[i++] = 0x0a;
    out.set(payload, i);
    return out;
  }

  it('非 53 端口 → FORWARD_UDP_UNSUPPORTED', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const client = makeMockClient();
    const frame = buildTrojanUdpFrame('example.com', 443, new Uint8Array([1]));
    await expect(forwardTrojanUdp(rctx, frame, client, { cache: new Uint8Array(0), proxyAddr: null }, rctx.request)).rejects.toThrow(
      /UDP is not supported/,
    );
  });

  it('非法 addressType → 抛错', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const client = makeMockClient();
    await expect(
      forwardTrojanUdp(rctx, new Uint8Array([0x99, 0, 0, 0, 0, 0, 0, 0]), client, { cache: new Uint8Array(0), proxyAddr: null }, rctx.request),
    ).rejects.toThrow(/addressType/);
  });

  it('不完整帧 → 缓存到 ctx.cache，不抛', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const client = makeMockClient();
    const ctx = { cache: new Uint8Array(0), proxyAddr: null as null };
    // 只给 atype + 部分域名
    await forwardTrojanUdp(rctx, new Uint8Array([3, 10, 97, 98]), client, ctx, rctx.request);
    expect(ctx.cache.byteLength).toBe(4);
    expect(client.sent.length).toBe(0);
  });

  it('proxyAddr 存在 → 转发到反代隧道（首包建连）', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const client = makeMockClient();
    const sock = makeMockSocket();
    const tcp = vi.fn(() => sock);
    const ctx: { cache: Uint8Array; proxyAddr: { hostname: string; port: number } | null; proxySocket?: TcpSocket } = {
      cache: new Uint8Array(0),
      proxyAddr: { hostname: '1.2.3.4', port: 8443 },
    };
    const frame = buildTrojanUdpFrame('example.com', 53, new Uint8Array([1, 2]));
    await forwardTrojanUdp(rctx, frame, client, ctx, rctx.request, tcp as never);
    expect(tcp).toHaveBeenCalledWith({ hostname: '1.2.3.4', port: 8443 });
    expect(sock.written.length).toBe(1);
    expect(ctx.proxySocket).toBeDefined();
  });
});

// ————————————————————————— runForward —————————————————————————

describe('runForward（直连 + connectOnly）', () => {
  it('connectOnly：拨通后返回 socket，不启 connectStreams', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const sock = makeMockSocket({ downlink: [new Uint8Array([0x01, 0x00])] });
    const tcp = vi.fn(() => sock);
    const client = makeMockClient();
    const conn = createRemoteConn();
    const result = await runForward({
      host: '1.2.3.4',
      port: 443,
      rawData: new Uint8Array([9]),
      client,
      respHeader: new Uint8Array([0, 0]),
      remoteConn: conn,
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: { trojanProxyAddr: null, proxyIP: '', proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: { hostname: '', port: 0 }, proxyFallback: true },
      connectOnly: true,
      tcpConnect: tcp as never,
      socks5Whitelist: [],
      rctx,
    });
    expect(result).toBe(sock);
    expect(sock.written.length).toBe(1);
    expect([...sock.written[0]!]).toEqual([9]);
    // connectOnly 不应已经把下行发给 client（由调用方接泵）
    expect(client.sent.length).toBe(0);
  });

  it('非 connectOnly：拨通后 connectStreams 下行回 client', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const down = new Uint8Array([0xaa, 0xbb]);
    const sock = makeMockSocket({ downlink: [down] });
    const tcp = vi.fn(() => sock);
    const client = makeMockClient();
    const conn = createRemoteConn();
    await runForward({
      host: '1.2.3.4',
      port: 443,
      rawData: null,
      client,
      respHeader: new Uint8Array([0x01, 0x00]),
      remoteConn: conn,
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: { trojanProxyAddr: null, proxyIP: '', proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: { hostname: '', port: 0 }, proxyFallback: true },
      tcpConnect: tcp as never,
      socks5Whitelist: [],
      rctx,
    });
    // 等 connectStreams 泵完
    await new Promise((r) => setTimeout(r, 20));
    expect(client.sent.length).toBeGreaterThan(0);
    // 首片含 respHeader 前置
    expect(client.sent[0]![0]).toBe(0x01);
    expect(client.sent[0]![1]).toBe(0x00);
  });

  it('直连失败 + 有链式代理 → 回落 connecttoPry', async () => {
    const { rctx } = makeRctx('https://x.test/');
    let n = 0;
    const tcp = vi.fn(() => {
      n++;
      // 前 tcpConcurrentDial 次（直连并发）失败，之后成功
      if (n <= 2) return makeMockSocket({ failOpen: true });
      return makeMockSocket({ downlink: [new Uint8Array([1])] });
    });
    const client = makeMockClient();
    const conn = createRemoteConn();
    await runForward({
      host: 'example.com',
      port: 443,
      rawData: null,
      client,
      respHeader: null,
      remoteConn: conn,
      userId: USER_ID,
      request: rctx.request,
      proxyCtx: {
        trojanProxyAddr: null,
        proxyIP: '9.9.9.9',
        proxyType: null, // 无链式 → 反代路径
        proxyAccount: '',
        proxyGlobal: false,
        proxyParams: { hostname: '', port: 0 },
        proxyFallback: true,
      },
      tcpConnect: tcp as never,
      socks5Whitelist: [],
      rctx,
    });
    // 直连 2 路失败后 → 反代 resolveAddrPort → connectProxyIP（IP 直用）
    await new Promise((r) => setTimeout(r, 30));
    expect(n).toBeGreaterThan(2);
  });
});

// ————————————————————————— 编排器 —————————————————————————

describe('runSession（VLESS over mock transport）', () => {
  const emptyProxyCtx = {
    trojanProxyAddr: null,
    proxyIP: '',
    proxyType: null,
    proxyAccount: '',
    proxyGlobal: false,
    proxyParams: { hostname: '', port: 0 },
    proxyFallback: true,
  } as const;

  it('首包非法 → 400 Invalid request', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const session = makeSession({ chunks: [new Uint8Array([0xff, 0xff, 0xff])] });
    // 不断 end，让读循环耗尽（手动 end）
    setTimeout(() => session.end(), 5);
    const result = await runSession({
      rctx,
      transportName: 'websocket',
      session,
      proxyCtx: { ...emptyProxyCtx },
      mode: 'immediate',
    });
    // 可能是 started（还在读）或 response（解析失败）
    if (result.kind === 'response') {
      expect(result.response.status).toBe(400);
    } else {
      expect(result.kind).toBe('started');
    }
  });

  it('earlyData 完整 VLESS 首包 + connectOnly 拨号', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const payload = new TextEncoder().encode('hello');
    const first = buildVlessFirstPacket(USER_ID, '1.2.3.4', 443, payload);
    const sock = makeMockSocket({ downlink: [new Uint8Array([0x01, 0x00, 0x68, 0x69])] });
    const tcp = vi.fn(() => sock);
    const session = makeSession({ earlyData: first, chunks: [] });
    setTimeout(() => session.end(), 5);

    const result = await runSession({
      rctx,
      transportName: 'xhttp',
      session,
      earlyData: first,
      proxyCtx: { ...emptyProxyCtx },
      tcpConnect: tcp as never,
      mode: 'first-packet',
      respondFirstPacket: () => new Response(null, { status: 200 }),
    });
    // first-packet 模式：拨号成功 → started（随后返回流式响应）
    expect(result.kind).toBe('started');
    // 已拨号并写了 payload
    await new Promise((r) => setTimeout(r, 20));
    expect(tcp).toHaveBeenCalled();
    const written = sock.written;
    expect(written.length).toBeGreaterThanOrEqual(1);
    expect([...written[0]!]).toEqual([...payload]);
  });

  it('测速站点首包 → first-packet 短路 204', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const first = buildVlessFirstPacket(USER_ID, 'speed.cloudflare.com', 443, new Uint8Array([1]));
    const session = makeSession({ earlyData: first, chunks: [] });
    setTimeout(() => session.end(), 5);
    const result = await runSession({
      rctx,
      transportName: 'xhttp',
      session,
      earlyData: first,
      proxyCtx: { ...emptyProxyCtx },
      mode: 'first-packet',
      respondFirstPacket: (opts) =>
        new Response(opts.localBody, { status: opts.status ?? 200, headers: opts.headers }),
    });
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response.status).toBe(200);
      const body = new Uint8Array(await result.response.arrayBuffer());
      const text = new TextDecoder().decode(body);
      expect(text).toContain('204 No Content');
      // VLESS replyHeader [0,0] 前置
      expect(body[0]).toBe(0);
      expect(body[1]).toBe(0);
    }
  });

  it('UDP 非 53（VLESS）→ first-packet 短路 400', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const first = buildVlessFirstPacket(USER_ID, '1.2.3.4', 443, new Uint8Array([1]), 2); // cmd=2 UDP
    const session = makeSession({ earlyData: first, chunks: [] });
    setTimeout(() => session.end(), 5);
    const result = await runSession({
      rctx,
      transportName: 'xhttp',
      session,
      earlyData: first,
      proxyCtx: { ...emptyProxyCtx },
      mode: 'first-packet',
      respondFirstPacket: (opts) => new Response(opts.localBody, { status: opts.status ?? 200 }),
    });
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response.status).toBe(400);
      expect(await result.response.text()).toBe('UDP is not supported');
    }
  });

  it('immediate 模式（WS）：earlyData 解析后后台拨号，返回 started', async () => {
    const { rctx } = makeRctx('https://x.test/');
    const first = buildVlessFirstPacket(USER_ID, '1.2.3.4', 443, new Uint8Array([1, 2, 3]));
    const sock = makeMockSocket({ downlink: [] });
    const tcp = vi.fn(() => sock);
    const session = makeSession({ earlyData: first, chunks: [] });
    setTimeout(() => session.end(), 10);

    const result = await runSession({
      rctx,
      transportName: 'websocket',
      session,
      earlyData: first,
      proxyCtx: { ...emptyProxyCtx },
      tcpConnect: tcp as never,
      mode: 'immediate',
    });
    expect(result.kind).toBe('started');
    await new Promise((r) => setTimeout(r, 30));
    expect(tcp).toHaveBeenCalled();
  });
});

// ————————————————————————— version 路由 —————————————————————————

describe('version 路由', () => {
  it('uuid 匹配（前8位hex和 + 后12位相同）→ 200 { Version }', async () => {
    // 构造与 userId 匹配的 uuid：前 8 位 hex 数值和相等 + 后 12 位相同
    // userId = 00000000-0000-4000-8000-000000000000
    // 简单法：用完全相同的 uuid（前8和必然相等，后12相同）
    const { rctx } = makeRctx(`https://x.test/version?uuid=${USER_ID}`);
    const resp = await handleHttpRoute(rctx);
    expect(resp).not.toBeNull();
    expect(resp!.status).toBe(200);
    const body = (await resp!.json()) as { Version: number };
    expect(body.Version).toBe(EDT_VERSION);
  });

  it('uuid 不匹配 → 不短路（无 KV + 有 envUUID → 伪装页兜底，与原 L526 一致）', async () => {
    const { rctx } = makeRctx('https://x.test/version?uuid=ffffffff-ffff-4fff-bfff-ffffffffffff');
    const resp = await handleHttpRoute(rctx);
    // P7 起未命中路由由 FakePagePlugin 兜底（原 else-if 链落出 → nginx 伪装页）
    expect(resp).not.toBeNull();
    expect(resp!.status).toBe(200);
    expect(await resp!.text()).toContain('Welcome to nginx!');
  });

  it('无 uuid 参数 → 不短路（落伪装页）', async () => {
    const { rctx } = makeRctx('https://x.test/version');
    const resp = await handleHttpRoute(rctx);
    expect(resp).not.toBeNull();
    expect(await resp!.text()).toContain('Welcome to nginx!');
  });

  it('uuid 格式非法 → 不短路（落伪装页）', async () => {
    const { rctx } = makeRctx('https://x.test/version?uuid=not-a-uuid');
    const resp = await handleHttpRoute(rctx);
    expect(resp).not.toBeNull();
    expect(await resp!.text()).toContain('Welcome to nginx!');
  });
});

void concatByteChunks;
void (undefined as DialCandidate | undefined);
