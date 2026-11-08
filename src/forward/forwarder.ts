/**
 * TCP 转发核心（原 _worker.js forwardataTCP，12 参收敛为对象入参，行为等价移植）。
 *
 * 职责：出站拨号调度（直连 / ProxyIP 反代 / 链式代理 P6）+ 连接世代安装 +
 * 上下行泵接线。不理解协议/传输细节 —— 那是会话编排器的职责。
 */
import type { RequestContext } from '../context';
import { TunnelError } from '../errors';
import { effectiveByteLength, toUint8Array } from '../utils/bytes';
import { isIPHostname } from '../utils/net';
import { beginTcpGeneration, type RemoteConn } from './generation';
import { createRequestTcpConnector, connectDirect, connectProxyIP, writeFirstPacket, type TcpConnector, type TcpSocket } from './dialer';
import { connectStreams } from './streams';
import { resolveAddrPort } from './resolve';
import type { ProxyContext } from './proxy-ctx';
import type { ClientLikeSocket } from './grain';
import { BRAND_PROXYIP, BRAND_TP1_ID } from '../services/brand';
import { getPlugins } from '../plugins/registry';
import type { DialPlan } from '../plugins/base';
import { chainRegistry } from '../chain/registry';

/** forwardataTCP 对象入参（原 12 参） */
export interface ForwardTcpParams {
  host: string;
  port: number;
  /** 协议头之后的剩余客户端数据（首包载荷；空则不写） */
  rawData: Uint8Array | null;
  /** 客户端适配器（WS serverSock / gRPC 桥 / xHTTP 桥） */
  client: ClientLikeSocket;
  /** 需先写回客户端的响应头（VLESS [version,0]；只取一次） */
  respHeader: Uint8Array | null;
  remoteConn: RemoteConn;
  userId: string;
  request: Request | null;
  proxyCtx: ProxyContext;
  /** Trojan 允许经 trojanProxyAddr 反代（原 allowTrojanProxy） */
  allowTrojanProxy?: boolean;
  /** Trojan 完整首包（含协议头；反代时先发握手） */
  trojanProxyFirstPacket?: Uint8Array | null;
  /** 只拨号不启泵（xHTTP 用，原 connectOnly） */
  connectOnly?: boolean;
  /** 可注入的 TCP 工厂（测试用；缺省从 request.fetcher.connect 提取） */
  tcpConnect?: TcpConnector;
  /** 链式代理白名单（原模块级 socks5Whitelist；由 context 传入） */
  socks5Whitelist?: string[];
  /** 每请求日志/调优上下文（编排器传入；缺省轻量适配） */
  rctx?: RequestContext;
}

/** 出站计划（插件 onBeforeDial 可改写；DESIGN.md §4.5） */
export interface ForwardPlan extends DialPlan {
  host: string;
  port: number;
}

/** SOCKS5 白名单匹配（原 forwardataTCP L2460 的 RegExp 语义） */
function matchWhitelist(host: string, patterns: string[]): boolean {
  return patterns.some((p) => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host));
}

/**
 * TCP 转发（原 forwardataTCP）。
 *
 * 流程：链式/全局白名单命中 → connecttoPry；否则直连（preload 竞速）→
 * 失败回落 connecttoPry。连接安装后接 connectStreams 上下行泵。
 * connectOnly=true 时只返回已拨通的 socket（xHTTP 自管泵）。
 */
export async function runForward(params: ForwardTcpParams): Promise<TcpSocket | true | null> {
  const {
    host: rawHost,
    port: portNum,
    rawData,
    client,
    respHeader,
    remoteConn,
    userId,
    request,
    proxyCtx,
    allowTrojanProxy = false,
    trojanProxyFirstPacket = null,
    connectOnly = false,
  } = params;

  // —— 插件 onBeforeDial 钩子（可改写出站计划）——
  // rctx 由调用方（编排器）传入；缺失时用轻量适配（仅 log/dial）
  const logCtx: RequestContext =
    (params as { rctx?: RequestContext }).rctx ??
    ({
      log: () => {},
      error: () => {},
      dial: { tcpConcurrentDial: 2, proxyConcurrentDial: 1, preloadRaceDial: false },
    } as unknown as RequestContext);

  let host = rawHost;
  let plan: ForwardPlan = { host, port: portNum, userId, proxyType: proxyCtx.proxyType, proxyParams: proxyCtx.proxyParams };
  for (const plugin of getPlugins()) {
    if (plugin.onBeforeDial) plan = await plugin.onBeforeDial(plan, logCtx);
  }
  host = plan.host;
  const planPort = plan.port;

  const ctxProxyIP = proxyCtx.proxyIP || '';
  const ctxProxyType = proxyCtx.proxyType !== undefined ? proxyCtx.proxyType : null;
  const ctxProxyGlobal = proxyCtx.proxyGlobal !== undefined ? proxyCtx.proxyGlobal : false;
  const ctxProxyParams = proxyCtx.proxyParams || { hostname: '', port: 0 };
  const ctxProxyFallback = proxyCtx.proxyFallback !== undefined ? proxyCtx.proxyFallback : true;
  let proxyListIndex = 0;

  logCtx.log?.('[TCP转发]', `目标: ${host}:${portNum} | 反代IP: ${ctxProxyIP} | 反代兜底: ${ctxProxyFallback ? '是' : '否'} | 反代类型: ${ctxProxyType || 'proxyip'} | 全局: ${ctxProxyGlobal ? '是' : '否'}`);

  let firstPacketSentViaProxy = false;
  const tcpConnect = params.tcpConnect ?? createRequestTcpConnector(request);
  const useTrojanProxy = allowTrojanProxy && (proxyCtx.trojanProxyAddr || null);
  const trojanProxyTarget = useTrojanProxy ? proxyCtx.trojanProxyAddr : null;
  const trojanProxyHandshake = useTrojanProxy ? extractTrojanProxyHandshake(trojanProxyFirstPacket, rawData) : null;

  let pendingRespHeader = respHeader;
  const takeRespHeader = () => {
    const header = pendingRespHeader;
    pendingRespHeader = null;
    return header;
  };
  if (!Number.isInteger(remoteConn.generation)) remoteConn.generation = 0;

  const installCurrentConnection = async (
    socket: TcpSocket,
    generation: number,
    downlinkDrain: Promise<unknown>,
    retryFunc: (() => Promise<void>) | null = null,
  ): Promise<TcpSocket | true> => {
    try {
      await downlinkDrain;
    } catch (e) {
      if (remoteConn.downlinkDrain === downlinkDrain) remoteConn.downlinkDrain = Promise.resolve();
      try {
        socket?.close?.();
      } catch {
        /* ignore */
      }
      if (remoteConn.generation === generation) closeClientQuietly(client);
      throw e;
    }
    if (remoteConn.downlinkDrain === downlinkDrain) remoteConn.downlinkDrain = Promise.resolve();
    const isConnStillValid = () => remoteConn.generation === generation && remoteConn.socket === socket;
    if (remoteConn.generation !== generation || client.readyState !== 1) {
      try {
        socket?.close?.();
      } catch {
        /* ignore */
      }
      if (remoteConn.generation === generation) remoteConn.socket = null;
      throw new TunnelError('FORWARD_SUPERSEDED', 'connection superseded or client closed');
    }
    remoteConn.socket = socket;
    if (connectOnly) return socket;
    connectStreams(socket, client, takeRespHeader, retryFunc, isConnStillValid, remoteConn).catch((err) => {
      if (!isConnStillValid()) return;
      logCtx.log?.('[TCP下行]', `处理失败: ${(err as Error)?.message || err}`);
      try {
        socket?.close?.();
      } catch {
        /* ignore */
      }
      closeClientQuietly(client);
    });
    return true;
  };

  async function connectAndInstall(
    dial: () => Promise<TcpSocket>,
    generation: number,
    downlinkDrain: Promise<unknown>,
    retryFunc: (() => Promise<void>) | null = null,
  ): Promise<TcpSocket | true> {
    const socket = await dial();
    try {
      return await installCurrentConnection(socket, generation, downlinkDrain, retryFunc);
    } catch (err) {
      try {
        socket?.close?.();
      } catch {
        /* ignore */
      }
      throw err;
    }
  }

  async function connecttoPry(allowSendFirstPacket = true): Promise<void> {
    if (remoteConn.connectingPromise) {
      await remoteConn.connectingPromise;
      return;
    }
    const { generation: currentGeneration, downlinkDrain } = beginTcpGeneration(remoteConn);

    let sendFirstPacketNow = false;
    let currentFirstPacket: Uint8Array | null = null;
    if (useTrojanProxy) {
      if (allowSendFirstPacket && !firstPacketSentViaProxy && effectiveByteLength(trojanProxyFirstPacket) > 0) {
        currentFirstPacket = trojanProxyFirstPacket!;
        sendFirstPacketNow = effectiveByteLength(rawData) > 0;
      } else {
        currentFirstPacket = trojanProxyHandshake;
      }
    } else {
      sendFirstPacketNow = allowSendFirstPacket && !firstPacketSentViaProxy && effectiveByteLength(rawData) > 0;
      currentFirstPacket = sendFirstPacketNow ? rawData : null;
    }

    const currentConnectTask = (async () => {
      let newSocket: TcpSocket | null = null;
      try {
        if (useTrojanProxy) {
          logCtx.log?.('[木马反代]', `代理到: ${host}:${planPort}`);
          newSocket = await connectTrojanProxy(currentFirstPacket, tcpConnect, trojanProxyTarget!);
        } else if (ctxProxyType && chainRegistry.has(ctxProxyType)) {
          // —— 链式代理五子类（SOCKS5/HTTP/HTTPS/TURN/SSTP，P6）——
          logCtx.log?.(`[${ctxProxyType.toUpperCase()}代理]`, `代理到: ${host}:${planPort}`);
          const provider = chainRegistry.get(ctxProxyType)!;
          const dialed = await provider.dial({
            proxy: {
              hostname: ctxProxyParams.hostname,
              port: ctxProxyParams.port,
              username: ctxProxyParams.username,
              password: ctxProxyParams.password,
            },
            target: { host, port: planPort },
            initialData: currentFirstPacket,
            tcpConnect,
          });
          newSocket = dialed.socket as TcpSocket;
        } else {
          logCtx.log?.('[反代连接]', `代理到: ${host}:${planPort}`);
          const allProxyList = await resolveAddrPort(logCtx, ctxProxyIP, host, userId);
          const result = await connectProxyIP(logCtx, tcpConnect, `${BRAND_PROXYIP}.tp1.${BRAND_TP1_ID}.xyz`, 1, currentFirstPacket, allProxyList, ctxProxyFallback, proxyListIndex);
          newSocket = result.socket;
          proxyListIndex = result.nextIndex;
        }
        await installCurrentConnection(newSocket, currentGeneration, downlinkDrain);
        if (sendFirstPacketNow) firstPacketSentViaProxy = true;
      } catch (err) {
        try {
          newSocket?.close?.();
        } catch {
          /* ignore */
        }
        if (remoteConn.generation === currentGeneration) {
          remoteConn.socket = null;
          closeClientQuietly(client);
          throw err;
        }
      }
    })();

    remoteConn.connectingPromise = currentConnectTask;
    try {
      await currentConnectTask;
    } finally {
      if (remoteConn.connectingPromise === currentConnectTask) {
        remoteConn.connectingPromise = null;
      }
    }
  }

  remoteConn.retryConnect = async () => connecttoPry(!firstPacketSentViaProxy);

  const whitelist = params.socks5Whitelist ?? [];
  if (ctxProxyType && (ctxProxyGlobal || matchWhitelist(host, whitelist))) {
    logCtx.log?.('[TCP转发]', '启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理');
    try {
      await connecttoPry();
      if (connectOnly) return remoteConn.socket as TcpSocket;
    } catch (err) {
      logCtx.log?.('[TCP转发]', `SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${(err as Error).message}`);
      throw err;
    }
  } else {
    let directGeneration = remoteConn.generation;
    try {
      logCtx.log?.('[TCP转发]', `尝试直连到: ${host}:${planPort}`);
      const generationConn = beginTcpGeneration(remoteConn);
      directGeneration = generationConn.generation;
      const initialSocket = await connectAndInstall(
        () => connectDirect(logCtx, tcpConnect, host, planPort, rawData, true),
        directGeneration,
        generationConn.downlinkDrain,
        async () => {
          if (remoteConn.generation !== directGeneration || remoteConn.socket !== initialSocket) return;
          await connecttoPry();
        },
      );
      if (connectOnly) return initialSocket as TcpSocket;
    } catch (err) {
      logCtx.log?.('[TCP转发]', `直连 ${host}:${planPort} 失败: ${(err as Error).message}`);
      if (remoteConn.generation !== directGeneration) throw err;
      if (err instanceof Error && err.name === '预加载解析为空') {
        closeClientQuietly(client);
        throw err;
      }
      if (client.readyState !== 1) throw err;
      await connecttoPry();
      if (connectOnly) return remoteConn.socket as TcpSocket;
    }
  }
  return true;
}

/** 木马反代：拨通并写首包（原 connectTrojanProxy） */
async function connectTrojanProxy(
  firstPacketData: Uint8Array | null,
  tcpConnect: TcpConnector,
  trojanProxyTarget: { hostname: string; port: number },
): Promise<TcpSocket> {
  if (!trojanProxyTarget) throw new TunnelError('CHAIN_TROJAN_ADDR', 'trojan fallback is not configured');
  const socket = tcpConnect({ hostname: stripBrackets(trojanProxyTarget.hostname), port: trojanProxyTarget.port });
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  try {
    if (socket.opened) await socket.opened;
    if (effectiveByteLength(firstPacketData) > 0) {
      writer = socket.writable.getWriter();
      await writer.write(toUint8Array(firstPacketData));
    }
    return socket;
  } catch (error) {
    try {
      socket?.close?.();
    } catch {
      /* ignore */
    }
    throw error;
  } finally {
    try {
      writer?.releaseLock();
    } catch {
      /* ignore */
    }
  }
}

/** 从完整 Trojan 首包中切出「仅握手」部分（原 extractTrojanProxyHandshake） */
function extractTrojanProxyHandshake(firstPacketData: Uint8Array | null, rawData: Uint8Array | null): Uint8Array | null {
  const firstPacket = toUint8Array(firstPacketData);
  const payload = toUint8Array(rawData);
  if (!payload.byteLength) return firstPacket;
  const handshakeLen = firstPacket.byteLength - payload.byteLength;
  if (handshakeLen <= 0) return firstPacket;
  for (let i = 0; i < payload.byteLength; i++) {
    if (firstPacket[handshakeLen + i] !== payload[i]) return firstPacket;
  }
  return firstPacket.subarray(0, handshakeLen);
}

function stripBrackets(hostname: string): string {
  const host = String(hostname || '').trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function closeClientQuietly(socket: ClientLikeSocket): void {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) socket.close?.();
  } catch {
    /* ignore */
  }
}

void writeFirstPacket;
void isIPHostname;
