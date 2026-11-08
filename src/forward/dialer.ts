/**
 * 并发拨号 / 竞速预连 / ProxyIP 反代（原 _worker.js forwardataTCP 内嵌的
 * openTcpConnection / openCandidatesConcurrent / buildPreloadRaceCandidates /
 * connectDirect / connectProxyIP，行为等价移植）。
 */
import type { RequestContext } from '../context';
import { TunnelError } from '../errors';
import { dohQuery } from '../services/doh';
import { isIPHostname, isIPv4 } from '../utils/net';
import { toUint8Array } from '../utils/bytes';

/** 拨号候选（原 candidate） */
export interface DialCandidate {
  hostname: string;
  port: number;
  attempt?: number;
  index?: number;
  resolvedFrom?: string;
}

/** 底层 TCP 连接（CF fetcher.connect 返回的 Socket 子集） */
export interface TcpSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed?: Promise<unknown>;
  close?(): void;
}

/** TCP 工厂：由 Request.fetcher.connect 包装（原 createRequestTcpConnector）
 *  init 对应 fetcher.connect 第二参（secureTransport / allowHalfOpen，HTTP·SSTP 链式用）。 */
export type TcpConnectInit = { secureTransport?: 'on' | 'off'; allowHalfOpen?: boolean };
export type TcpConnector = (options: { hostname: string; port: number }, init?: TcpConnectInit) => TcpSocket;

/** 从 Request 提取 TCP 连接器（原 createRequestTcpConnector；无 fetcher 时抛错） */
export function createRequestTcpConnector(request: Request | null): TcpConnector {
  const requestObj = request as unknown as { fetcher?: { connect?: (options: unknown, init?: unknown) => unknown } } | null;
  const fetcher = requestObj?.fetcher;
  if (!fetcher || typeof fetcher.connect !== 'function') {
    throw new TunnelError('FORWARD_NO_CONNECTOR', 'request.fetcher.connect unavailable');
  }
  return ((options: { hostname: string; port: number }, init?: unknown) =>
    init === undefined ? (fetcher.connect!(options) as TcpSocket) : (fetcher.connect!(options, init) as TcpSocket)) as TcpConnector;
}

/** 连接超时（原 connectTimeoutMs = 1000） */
export const CONNECT_TIMEOUT_MS = 1000;

async function waitForConnectionOpen(remoteSock: TcpSocket, timeoutMs = CONNECT_TIMEOUT_MS): Promise<void> {
  const opened = remoteSock.opened;
  if (!opened || typeof (opened as Promise<unknown>).then !== 'function') {
    // opened 非 promise（异常运行时）→ 视为已就绪，交由后续读写暴露错误
    return;
  }
  await Promise.race([
    opened,
    new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs)),
  ]);
}

/** 打开单条 TCP 并等待 opened（原 openTcpConnection） */
export async function openTcpConnection(tcpConnect: TcpConnector, address: string, port: number): Promise<TcpSocket> {
  const remoteSock = tcpConnect({ hostname: address, port });
  try {
    await waitForConnectionOpen(remoteSock);
    return remoteSock;
  } catch (err) {
    try {
      remoteSock?.close?.();
    } catch {
      /* ignore */
    }
    throw err;
  }
}

/** 写首包（原 writeFirstPacket） */
export async function writeFirstPacket(socket: TcpSocket, data: Uint8Array | null | undefined): Promise<void> {
  if (!data || data.byteLength <= 0) return;
  const writer = socket.writable.getWriter();
  try {
    await writer.write(toUint8Array(data));
  } finally {
    try {
      writer.releaseLock();
    } catch {
      /* ignore */
    }
  }
}

/** 并发竞速拨号：Promise.any 取先成者，败者关闭（原 openCandidatesConcurrent） */
export async function openCandidatesConcurrent(
  tcpConnect: TcpConnector,
  candidateList: DialCandidate[],
): Promise<{ socket: TcpSocket; candidate: DialCandidate }> {
  if (candidateList.length === 1) {
    const candidate = candidateList[0]!;
    return { socket: await openTcpConnection(tcpConnect, candidate.hostname, candidate.port), candidate };
  }
  const attempts = candidateList.map((candidate) =>
    openTcpConnection(tcpConnect, candidate.hostname, candidate.port).then((socket) => ({ socket, candidate })),
  );
  let winner: { socket: TcpSocket; candidate: DialCandidate } | null = null;
  try {
    winner = await Promise.any(attempts);
    return winner;
  } finally {
    if (winner) {
      for (const attempt of attempts) {
        attempt
          .then(({ socket }) => {
            if (socket !== winner!.socket) {
              try {
                socket?.close?.();
              } catch {
                /* ignore */
              }
            }
          })
          .catch(() => {});
      }
    }
  }
}

/**
 * 预加载竞速候选：DoH 查 A/AAAA 后取前 N 个 IP（原 buildPreloadRaceCandidates）。
 * 返回 null 表示不可用（开关关 / 目标已是 IP / 无解析结果）。
 */
export async function buildPreloadRaceCandidates(
  ctx: RequestContext,
  address: string,
  port: number,
): Promise<DialCandidate[] | null> {
  if (!ctx.dial.preloadRaceDial || isIPHostname(address)) return null;
  ctx.log('[TCP直连]', `预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
  const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, 'A'), dohQuery(address, 'AAAA')]);
  const ipv4List = [...new Set(aRecords.flatMap((r) => (r.type === 1 && typeof r.data === 'string' && isIPv4(r.data) ? [r.data] : [])))];
  const ipv6List = [...new Set(aaaaRecords.flatMap((r) => (r.type === 28 && typeof r.data === 'string' && isIPHostname(r.data) ? [r.data] : [])))];
  const dialLimit = Math.max(1, ctx.dial.tcpConcurrentDial | 0);
  const ipList =
    ipv4List.length >= dialLimit ? ipv4List.slice(0, dialLimit) : ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
  const recordTypeUsed = ipv4List.length > 0 ? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A') : 'AAAA';
  if (ipList.length === 0) {
    ctx.log('[TCP直连]', `${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
    return null;
  }
  ctx.log(
    '[TCP直连]',
    `${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${recordTypeUsed}记录，竞速拨号 ${ipList.length}/${dialLimit}: ${ipList.join(', ')}`,
  );
  return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}

/**
 * 直连拨号（原 connectDirect）：
 * 可选 preload 竞速 → 否则 tcpConcurrentDial 路同 hostname 并发 → 写首包。
 */
export async function connectDirect(
  ctx: RequestContext,
  tcpConnect: TcpConnector,
  address: string,
  port: number,
  data: Uint8Array | null = null,
  enablePreload = false,
): Promise<TcpSocket> {
  const preloadCandidateList = enablePreload ? await buildPreloadRaceCandidates(ctx, address, port) : null;
  const candidateList: DialCandidate[] =
    preloadCandidateList ||
    Array.from({ length: Math.max(1, ctx.dial.tcpConcurrentDial) }, (_, attempt) => ({ hostname: address, port, attempt }));
  ctx.log(
    '[TCP直连]',
    preloadCandidateList
      ? `并发尝试 ${candidateList.length} 路: ${candidateList.map((c) => `${c.hostname}:${c.port}`).join(', ')}`
      : `并发尝试 ${candidateList.length} 路: ${address}:${port}`,
  );
  let socket: TcpSocket | null = null;
  try {
    const connectResult = await openCandidatesConcurrent(tcpConnect, candidateList);
    socket = connectResult.socket;
    ctx.log('[TCP直连]', `拨号成功 ${connectResult.candidate.hostname}:${connectResult.candidate.port}`);
    if (preloadCandidateList) {
      const winner = connectResult.candidate;
      ctx.log('[TCP直连]', `预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
    }
    await writeFirstPacket(socket, data);
    ctx.log('[TCP直连]', `首包已写 ${data?.byteLength ?? 0}B`);
    return socket;
  } catch (err) {
    try {
      socket?.close?.();
    } catch {
      /* ignore */
    }
    if (preloadCandidateList) ctx.log('[TCP直连]', `预加载竞速失败: ${(err as Error).message || err}`);
    throw err;
  }
}

/**
 * ProxyIP 反代拨号（原 connectProxyIP）：
 * 按 proxyConcurrentDial 分批并发尝试代理列表；全部失败后按 allowProxyFallback 决定是否回落直连。
 */
export async function connectProxyIP(
  ctx: RequestContext,
  tcpConnect: TcpConnector,
  address: string,
  port: number,
  data: Uint8Array | null,
  allProxyList: Array<[string, number]>,
  allowProxyFallback: boolean,
  startIndex = 0,
): Promise<{ socket: TcpSocket; nextIndex: number }> {
  let proxyListIndex = startIndex;
  if (allProxyList && allProxyList.length > 0) {
    const actualConcurrency = Math.max(1, Math.floor(Number(ctx.dial.proxyConcurrentDial) || 1));
    for (let i = 0; i < allProxyList.length; i += actualConcurrency) {
      const candidateList: DialCandidate[] = [];
      for (let j = 0; j < actualConcurrency && i + j < allProxyList.length; j++) {
        const index = (proxyListIndex + i + j) % allProxyList.length;
        const [proxyAddr, proxyPort] = allProxyList[index]!;
        candidateList.push({ hostname: proxyAddr, port: proxyPort, index });
      }
      let socket: TcpSocket | null = null;
      let candidate: DialCandidate | null = null;
      try {
        ctx.log('[反代连接]', `并发尝试 ${candidateList.length} 路: ${candidateList.map((c) => `${c.hostname}:${c.port}`).join(', ')}`);
        const connectResult = await openCandidatesConcurrent(tcpConnect, candidateList);
        socket = connectResult.socket;
        candidate = connectResult.candidate;
        await writeFirstPacket(socket, data);
        ctx.log('[反代连接]', `成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
        return { socket, nextIndex: candidate.index ?? 0 };
      } catch (err) {
        try {
          socket?.close?.();
        } catch {
          /* ignore */
        }
        ctx.log('[反代连接]', `本批连接失败: ${(err as Error).message || err}`);
      }
    }
  }

  if (allowProxyFallback) {
    const socket = await connectDirect(ctx, tcpConnect, address, port, data, false);
    return { socket, nextIndex: proxyListIndex };
  }
  throw new TunnelError('FORWARD_PROXY_EXHAUSTED', '[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
}
