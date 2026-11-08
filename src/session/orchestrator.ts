/**
 * 会话编排器（DESIGN.md §5 代理链路 2-5 步）。
 *
 * 把 Transport ↔ Protocol ↔ Forwarder 串起来：
 *   earlyData / readable 首包 → Protocol.sniff/parse → 测速/UDP 短路 →
 *   runForward 拨号 → 上行泵（codec.uplink → 远端）+ 下行泵（远端 → grain → 客户端）。
 *
 * 三传输差异（与原 handleWs/Grpc/Xhttp 一致）：
 *   WS     —— 返回 101 后后台泵；earlyData 带外；
 *   gRPC   —— 立即返回流式 200，首包在后台处理（失败关流）；
 *   xHTTP  —— 先读首包（可短路 204/400/502），再拨号返回流式 200。
 */
import type { RequestContext } from '../context';
import { TunnelError } from '../errors';
import type { TransportSession } from '../transport/base';
import { selectProtocol } from '../protocol/registry';
import type { DuplexCodec, ParsedRequest, ProtocolHints } from '../protocol/base';
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../utils/bytes';
import { runForward } from '../forward/forwarder';
import { createRemoteConn, invalidateTcpGeneration, type RemoteConn } from '../forward/generation';
import { createUplinkWriteQueue, createDownlinkGrainSender, createUplinkCoalesceStream, type ClientLikeSocket, type UplinkWriteQueue } from '../forward/grain';
import { forwardDnsTcp, forwardTrojanUdp, createTrojanUdpCtx, type TrojanUdpCtx } from '../forward/udp';
import { isSpeedTestSite, buildLocal204Response, buildWsLocal204Response } from '../forward/speedtest';
import { connectStreams } from '../forward/streams';
import type { ProxyContext } from '../forward/proxy-ctx';
import type { TcpConnector, TcpSocket } from '../forward/dialer';

/** 编排器入参 */
export interface OrchestratorParams {
  rctx: RequestContext;
  transportName: string;
  session: TransportSession;
  /** WS earlyData（带外首段；gRPC/xHTTP 恒 undefined） */
  earlyData?: Uint8Array;
  proxyCtx: ProxyContext;
  /** 可注入 TCP 工厂（测试） */
  tcpConnect?: TcpConnector;
  socks5Whitelist?: string[];
  /**
   * 响应模式：
   *   'immediate' —— WS / gRPC：立即返回（101 / 流式 200），首包后台处理；
   *   'first-packet' —— xHTTP：先读首包，可短路（测速 204 / UDP 400 / 拨号 502），否则流式 200。
   */
  mode: 'immediate' | 'first-packet';
  /** first-packet 模式下的短路/流式响应构造（由传输层提供） */
  respondFirstPacket?: (opts: { localBody?: BodyInit; status?: number; headers?: HeadersInit }) => Response;
}

/** 编排结果 */
export type OrchestratorResult = { kind: 'response'; response: Response } | { kind: 'started' };

const FIRST_PACKET_MAX_BYTES = 64 * 1024;

/** 将 TransportSession 适配为 ClientLikeSocket（供 grain / connectStreams / UDP 使用）。
 * writer 惰性获取：xHTTP TCP 路径的下行泵会独占 session.writable.getWriter()，
 * 客户端适配器若提前锁住会导致 "WritableStream is locked"。 */
function sessionToClient(session: TransportSession): ClientLikeSocket {
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let closed = false;
  const getWriter = () => {
    if (!writer) writer = session.writable.getWriter();
    return writer;
  };
  return {
    get readyState() {
      return closed ? 3 : 1;
    },
    send(data: Uint8Array | ArrayBuffer | ArrayBufferView) {
      if (closed) return;
      const chunk = toUint8Array(data);
      if (!chunk.byteLength) return;
      try {
        void getWriter()
          .write(chunk)
          .catch(() => {
            closed = true;
          });
      } catch {
        closed = true;
      }
    },
    close() {
      if (closed) return;
      closed = true;
      try {
        if (writer) void writer.close();
      } catch {
        /* ignore */
      }
      try {
        writer?.releaseLock();
      } catch {
        /* ignore */
      }
      writer = null;
      session.close();
    },
  };
}

/**
 * 运行一个代理会话。
 * mode='first-packet' 时可能提前返回短路响应；否则启动后台泵并返回 { kind:'started' }。
 */
export async function runSession(params: OrchestratorParams): Promise<OrchestratorResult> {
  const { rctx, transportName, session, earlyData, proxyCtx, mode, respondFirstPacket } = params;
  rctx.log('session', `start mode=${mode} transport=${transportName} early=${earlyData?.byteLength ?? 0}B`);
  const client = sessionToClient(session);
  const remoteConn: RemoteConn = createRemoteConn();
  const hints: ProtocolHints = { userId: rctx.userId, query: rctx.url.searchParams };
  const trojanUdpCtx = createTrojanUdpCtx(proxyCtx.trojanProxyAddr);

  // —— 1. 读首包（earlyData 优先，否则从 readable 累积）——
  let pendingCipher: Uint8Array = earlyData && earlyData.byteLength > 0 ? new Uint8Array(earlyData) : new Uint8Array(0);
  // 用对象盒承载 reader：闭包内赋值后 TS 控制流分析无法回写外层 let 的窄化状态
  const readerBox: { current: ReadableStreamDefaultReader<Uint8Array> | null } = { current: null };

  const ensureReader = () => {
    if (!readerBox.current) readerBox.current = session.readable.getReader();
    return readerBox.current;
  };

  const readMore = async (): Promise<boolean> => {
    const r = ensureReader();
    const { done, value } = await r.read();
    if (done) return false;
    if (value && value.byteLength > 0) {
      rctx.log('session', `read ${value.byteLength}B`);
      pendingCipher = concatByteChunks(pendingCipher, value);
      return true;
    }
    return true; // 空块继续读
  };

  // 有 earlyData 时不先读流（保持原 WS「earlyData 先入队」语义）
  const hasEarly = pendingCipher.byteLength > 0;

  // —— 2. 选协议 + codec ——
  // 首包可能不完整（SS 需多块解密），循环直到 sniff 有结果且 parse 成功
  let protocol = selectProtocol(pendingCipher.byteLength > 0 ? pendingCipher : new Uint8Array([0]), hints);
  if (!protocol) {
    // 理论上 VLESS 恒兜底；防御性关闭
    session.close('no protocol');
    return { kind: 'response', response: new Response('Invalid request', { status: 400 }) };
  }
  const codec: DuplexCodec = protocol.codec(hints);

  // 用外层变量承接 parse 结果（闭包内赋值后 TS 控制流分析会窄化为 never，故显式声明）
  let parsedResult: ParsedRequest | null = null;
  let firstPlain: Uint8Array[] = [];

  const tryParseFromPending = async (): Promise<boolean> => {
    if (pendingCipher.byteLength === 0 && !hasEarly) return false;
    try {
      const plains = await codec.uplink(pendingCipher);
      pendingCipher = new Uint8Array(0);
      if (plains.length === 0) return false; // SS 握手未齐
      firstPlain = plains;
      const head = plains[0]!;
      parsedResult = protocol.parse(head, hints);
      return true;
    } catch (err) {
      // 数据不足 → 继续读；确定性协议错误 → 上抛
      if (err instanceof TunnelError) {
        const code = err.code;
        if (code.includes('INVALID_DATA') || code.includes('INVALID_HEADER') || code.includes('INVALID_PASSWORD') || code.includes('INVALID_UUID') || code.includes('INVALID_COMMAND')) {
          // 可能只是首包不完整 —— 若还有读机会则继续，否则抛
          if (pendingCipher.byteLength < FIRST_PACKET_MAX_BYTES) return false;
        }
        throw err;
      }
      throw err;
    }
  };

  // 有 earlyData 先尝试解析；否则先读一块
  if (hasEarly) {
    if (!(await tryParseFromPending())) {
      // earlyData 不够 → 继续读流
      while (pendingCipher.byteLength < FIRST_PACKET_MAX_BYTES) {
        const got = await readMore();
        if (!got) break;
        if (await tryParseFromPending()) break;
      }
    }
  } else {
    while (!parsedResult && pendingCipher.byteLength < FIRST_PACKET_MAX_BYTES) {
      const got = await readMore();
      if (!got) break;
      if (await tryParseFromPending()) break;
    }
  }

  if (!parsedResult) {
    try {
      readerBox.current?.releaseLock();
    } catch {
      /* ignore */
    }
    session.close('bad first packet');
    // first-packet 模式可短路 400；immediate 模式 101/200 已发出，只关会话
    if (mode === 'first-packet') {
      return { kind: 'response', response: new Response('Invalid request', { status: 400 }) };
    }
    return { kind: 'started' };
  }

  const firstPacket: ParsedRequest = parsedResult;
  const replyHeader = firstPacket.replyHeader ?? null;

  // 剩余明文（首块地址段之后的载荷 + 后续块）
  const headPlain = firstPlain[0]!;
  const extraPlains = firstPlain.slice(1);
  // parse 已消费 headPlain 中的地址段；payload 是地址段之后的部分
  let uplinkSeed: Uint8Array[] = [];
  if (firstPacket.payload.byteLength > 0) uplinkSeed.push(firstPacket.payload);
  uplinkSeed.push(...extraPlains);

  // —— 3. 测速短路 ——
  if (isSpeedTestSite(firstPacket.host) && proxyCtx.proxyType === null) {
    try {
      readerBox.current?.releaseLock();
    } catch {
      /* ignore */
    }
    if (mode === 'first-packet' && respondFirstPacket) {
      // xHTTP：独立 Response（原 L628-641，不带身份头）
      return {
        kind: 'response',
        response: respondFirstPacket({
          localBody: buildLocal204Response(replyHeader),
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' },
        }),
      };
    }
    // WS / gRPC：经会话流回 204
    client.send(buildWsLocal204Response(replyHeader) ?? buildLocal204Response(replyHeader));
    invalidateTcpGeneration(remoteConn);
    session.close('speedtest');
    return { kind: 'started' };
  }

  // —— 4. UDP 处理 ——
  if (firstPacket.udp) {
    const isTrojan = protocol.name === 'trojan';
    if (!isTrojan && firstPacket.port !== 53) {
      try {
        readerBox.current?.releaseLock();
      } catch {
        /* ignore */
      }
      if (mode === 'first-packet' && respondFirstPacket) {
        return { kind: 'response', response: respondFirstPacket({ localBody: 'UDP is not supported', status: 400 }) };
      }
      session.close('udp unsupported');
      return { kind: 'started' };
    }

    // VLESS replyHeader 需在首个下行分片前发送
    let udpRespHeader = replyHeader;
    const sendUdp = async (data: Uint8Array) => {
      if (isTrojan) {
        await forwardTrojanUdp(rctx, data, client, trojanUdpCtx, rctx.request, params.tcpConnect);
      } else {
        await forwardDnsTcp(rctx, data, client, udpRespHeader, rctx.request, null, params.tcpConnect);
        udpRespHeader = null;
      }
    };

    // 首包载荷
    if (firstPacket.payload.byteLength > 0) {
      if (isTrojan && trojanUdpCtx.proxyAddr) {
        // Trojan 反代：整条首包（含头）走隧道
        await forwardTrojanUdp(rctx, headPlain, client, trojanUdpCtx, rctx.request, params.tcpConnect);
      } else if (isTrojan) {
        await forwardTrojanUdp(rctx, firstPacket.payload, client, trojanUdpCtx, rctx.request, params.tcpConnect);
      } else {
        await forwardDnsTcp(rctx, firstPacket.payload, client, udpRespHeader, rctx.request, null, params.tcpConnect);
        udpRespHeader = null;
      }
    }

    if (mode === 'first-packet' && respondFirstPacket) {
      // xHTTP UDP：流式响应，后台继续读
      const response = respondFirstPacket({});
      void (async () => {
        try {
          for (;;) {
            const { done, value } = await ensureReader().read();
            if (done) break;
            if (!value?.byteLength) continue;
            await sendUdp(value);
          }
        } catch (err) {
          rctx.error('session', `UDP 泵失败: ${(err as Error).message}`);
        } finally {
          try {
            trojanUdpCtx.proxySocket?.close?.();
          } catch {
            /* ignore */
          }
          session.close('udp end');
        }
      })();
      return { kind: 'response', response };
    }

    // WS / gRPC：后台继续读
    void (async () => {
      try {
        for (;;) {
          const { done, value } = await ensureReader().read();
          if (done) break;
          if (!value?.byteLength) continue;
          await sendUdp(value);
        }
      } catch (err) {
        rctx.error('session', `UDP 泵失败: ${(err as Error).message}`);
      } finally {
        try {
          trojanUdpCtx.proxySocket?.close?.();
        } catch {
          /* ignore */
        }
        session.close('udp end');
      }
    })();
    return { kind: 'started' };
  }

  // —— 5. TCP：拨号 + 泵 ——
  // xHTTP first-packet：先 connectOnly 拨号，失败返回 502
  if (mode === 'first-packet') {
    try {
      const socket = await runForward({
        host: firstPacket.host,
        port: firstPacket.port,
        rawData: firstPacket.payload,
        client,
        respHeader: replyHeader,
        remoteConn,
        userId: rctx.userId,
        request: rctx.request,
        proxyCtx,
        allowTrojanProxy: protocol.name === 'trojan',
        trojanProxyFirstPacket: protocol.name === 'trojan' ? headPlain : null,
        connectOnly: true,
        tcpConnect: params.tcpConnect,
        socks5Whitelist: params.socks5Whitelist,
        rctx,
      } as Parameters<typeof runForward>[0] & { rctx: RequestContext });
      if (!socket || socket === true) {
        invalidateTcpGeneration(remoteConn);
        return { kind: 'response', response: new Response('bad gateway', { status: 502 }) };
      }
      // 接线：上行 coalescer → socket.writable；下行 socket.readable → responseStream
      // 由 respondFirstPacket 的调用方（xhttp 编排）负责 —— 这里返回 started 前启动泵
      startTcpPumps({
        rctx,
        client,
        remoteConn,
        socket: socket as TcpSocket,
        session,
        codec,
        uplinkSeed,
        replyHeader,
        ensureReader,
        proxyCtx,
        trojanUdpCtx,
        params,
        protocolName: protocol.name,
        firstPacket,
      });
      // 释放 reader 锁（pumps 会重新 getReader）
      try {
        readerBox.current?.releaseLock();
        readerBox.current = null;
      } catch {
        /* ignore */
      }
      return { kind: 'started' };
    } catch (err) {
      rctx.error('session', `连接失败: ${(err as Error).message}`);
      invalidateTcpGeneration(remoteConn);
      session.close('dial failed');
      return { kind: 'response', response: new Response('bad gateway', { status: 502 }) };
    }
  }

  // WS / gRPC：后台拨号 + 泵
  void (async () => {
    try {
      await runForward({
        host: firstPacket.host,
        port: firstPacket.port,
        rawData: firstPacket.payload,
        client,
        respHeader: replyHeader,
        remoteConn,
        userId: rctx.userId,
        request: rctx.request,
        proxyCtx,
        allowTrojanProxy: protocol.name === 'trojan',
        trojanProxyFirstPacket: protocol.name === 'trojan' ? headPlain : null,
        tcpConnect: params.tcpConnect,
        socks5Whitelist: params.socks5Whitelist,
        rctx,
      } as Parameters<typeof runForward>[0] & { rctx: RequestContext });
      // runForward 非 connectOnly 时内部已 connectStreams（下行 grain 已接）
      // 还需上行泵：session.readable → codec → remote writer
      startUplinkPump({
        rctx,
        remoteConn,
        session,
        codec,
        uplinkSeed,
        ensureReader,
        proxyCtx,
        trojanUdpCtx,
        params,
        protocolName: protocol.name,
        firstPacket,
        client,
      });
    } catch (err) {
      rctx.error('session', `转发失败: ${(err as Error).message}`);
      invalidateTcpGeneration(remoteConn);
      session.close('forward error');
    }
  })();

  return { kind: 'started' };
}

// —— 内部：上行/下行泵 ——

interface PumpCommon {
  rctx: RequestContext;
  remoteConn: RemoteConn;
  session: TransportSession;
  codec: DuplexCodec;
  uplinkSeed: Uint8Array[];
  ensureReader: () => ReadableStreamDefaultReader<Uint8Array>;
  proxyCtx: ProxyContext;
  trojanUdpCtx: TrojanUdpCtx;
  params: OrchestratorParams;
  protocolName: string;
  firstPacket: ParsedRequest;
}

interface UplinkPumpArgs extends PumpCommon {
  client: ClientLikeSocket;
}

interface TcpPumpArgs extends PumpCommon {
  client: ClientLikeSocket;
  socket: TcpSocket;
  replyHeader: Uint8Array | null;
}

/** 上行泵：seed + session.readable → codec.uplink → 远端 writer（经 UplinkWriteQueue） */
function startUplinkPump(args: UplinkPumpArgs): void {
  const { rctx, remoteConn, session, codec, uplinkSeed, ensureReader, proxyCtx, trojanUdpCtx, params, protocolName, firstPacket, client } = args;

  let currentWriteSocket: TcpSocket | null = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;

  const releaseRemoteWriter = () => {
    if (remoteWriter) {
      try {
        remoteWriter.releaseLock();
      } catch {
        /* ignore */
      }
      remoteWriter = null;
    }
    currentWriteSocket = null;
  };

  const uplinkQueue: UplinkWriteQueue = createUplinkWriteQueue({
    getWriter: () => {
      const socket = remoteConn.socket as TcpSocket | null;
      if (!socket) return null;
      if (socket !== currentWriteSocket) {
        releaseRemoteWriter();
        currentWriteSocket = socket;
        remoteWriter = socket.writable.getWriter();
      }
      return remoteWriter;
    },
    getConnectTask: () => remoteConn.connectingPromise,
    releaseWriter: releaseRemoteWriter,
    retryConnect: async () => {
      if (typeof remoteConn.retryConnect !== 'function') throw new Error('retry unavailable');
      await remoteConn.retryConnect();
    },
    closeConnection: () => {
      invalidateTcpGeneration(remoteConn);
      releaseRemoteWriter();
      closeClient(client);
      session.close('uplink error');
    },
    queueName: `${transportLabel(params.transportName)}上行`,
  });

  void (async () => {
    try {
      // seed（首包解析后的剩余明文）
      for (const chunk of uplinkSeed) {
        if (!chunk.byteLength) continue;
        if (!(await uplinkQueue.writeAndWait(chunk, false))) {
          // 无 writer（拨号未完成）→ 直接走 forward 重拨路径
          await runForward({
            host: firstPacket.host,
            port: firstPacket.port,
            rawData: chunk,
            client,
            respHeader: null,
            remoteConn,
            userId: rctx.userId,
            request: rctx.request,
            proxyCtx,
            allowTrojanProxy: protocolName === 'trojan',
            trojanProxyFirstPacket: protocolName === 'trojan' ? chunk : null,
            tcpConnect: params.tcpConnect,
            socks5Whitelist: params.socks5Whitelist,
            rctx,
          } as Parameters<typeof runForward>[0] & { rctx: RequestContext });
        }
      }

      // 持续读 session.readable
      for (;;) {
        const { done, value } = await ensureReader().read();
        if (done) break;
        if (!value?.byteLength) continue;

        // DNS / Trojan UDP 短路
        if (args.firstPacket.udp) {
          if (protocolName === 'trojan') await forwardTrojanUdp(rctx, value, client, trojanUdpCtx, rctx.request, params.tcpConnect);
          else await forwardDnsTcp(rctx, value, client, null, rctx.request, null, params.tcpConnect);
          continue;
        }

        const plains = await codec.uplink(value);
        for (const plain of plains) {
          if (!plain.byteLength) continue;
          const written = uplinkQueue.write(plain, false);
          if (written) continue;
          // 无连接 → 视为后续首包 / 重拨
          await runForward({
            host: firstPacket.host,
            port: firstPacket.port,
            rawData: plain,
            client,
            respHeader: null,
            remoteConn,
            userId: rctx.userId,
            request: rctx.request,
            proxyCtx,
            allowTrojanProxy: protocolName === 'trojan',
            trojanProxyFirstPacket: protocolName === 'trojan' ? plain : null,
            tcpConnect: params.tcpConnect,
            socks5Whitelist: params.socks5Whitelist,
            rctx,
          } as Parameters<typeof runForward>[0] & { rctx: RequestContext });
        }
      }
      await uplinkQueue.waitIdle();
    } catch (err) {
      rctx.error('session', `上行泵失败: ${(err as Error).message}`);
    } finally {
      uplinkQueue.clear();
      releaseRemoteWriter();
      invalidateTcpGeneration(remoteConn);
      try {
        trojanUdpCtx.proxySocket?.close?.();
      } catch {
        /* ignore */
      }
      closeClient(client);
    }
  })();
}

/** xHTTP connectOnly 后：上行 coalescer + 下行直 pipe（原 handleXhttpRequest L685-725） */
function startTcpPumps(args: TcpPumpArgs): void {
  const { rctx, client, remoteConn, socket, session, codec, uplinkSeed, replyHeader, ensureReader, proxyCtx, trojanUdpCtx, params, protocolName, firstPacket } = args;

  // 上行：session.readable → codec → coalescer → socket.writable
  const uplinkCoalescer = createUplinkCoalesceStream();
  const abort = new AbortController();
  const pipePromise = uplinkCoalescer.readable.pipeTo(socket.writable, { signal: abort.signal });
  void pipePromise.catch(() => abort.abort());

  void (async () => {
    try {
      for (const chunk of uplinkSeed) {
        if (chunk.byteLength) await uplinkCoalescer.write(chunk);
      }
      for (;;) {
        const { done, value } = await ensureReader().read();
        if (done) break;
        if (!value?.byteLength) continue;
        const plains = await codec.uplink(value);
        for (const plain of plains) {
          if (plain.byteLength) await uplinkCoalescer.write(plain);
        }
      }
    } catch (err) {
      rctx.error('session', `上行泵失败: ${(err as Error).message}`);
    } finally {
      try {
        await uplinkCoalescer.end();
      } catch {
        /* ignore */
      }
      await pipePromise.catch(() => {});
      invalidateTcpGeneration(remoteConn);
      try {
        trojanUdpCtx.proxySocket?.close?.();
      } catch {
        /* ignore */
      }
      closeClient(client);
      void session;
      void proxyCtx;
      void params;
      void protocolName;
      void firstPacket;
    }
  })();

  // 下行：replyHeader → session.writable；socket.readable → codec.downlink → session.writable
  // 注意：sessionToClient 是惰性 getWriter，此处先取锁独占下行
  void (async () => {
    let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
    try {
      writer = session.writable.getWriter();
      if (replyHeader && replyHeader.byteLength > 0) await writer.write(replyHeader);
      const reader = socket.readable.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value?.byteLength) continue;
        const frames = await codec.downlink(value);
        for (const frame of frames) {
          if (frame.byteLength) await writer.write(frame);
        }
      }
      try {
        await writer.close();
      } catch {
        /* ignore */
      }
    } catch (err) {
      rctx.error('session', `下行泵失败: ${(err as Error).message}`);
      try {
        await writer?.abort(err);
      } catch {
        /* ignore */
      }
    } finally {
      try {
        writer?.releaseLock();
      } catch {
        /* ignore */
      }
    }
  })();
}

function closeClient(client: ClientLikeSocket): void {
  try {
    if (client.readyState === 1 || client.readyState === 2) client.close?.();
  } catch {
    /* ignore */
  }
}

function transportLabel(name: string): string {
  return name === 'websocket' ? 'WS' : name === 'grpc' ? 'gRPC' : 'xHTTP';
}

void connectStreams;
void effectiveByteLength;
void (undefined as unknown as ReturnType<typeof createDownlinkGrainSender>);
