/**
 * UDP/DNS 转发（原 _worker.js forwardataudp / forwardTrojanUdp /
 * forwardTrojanUdpProxy，行为等价移植）。
 *
 * 出站固定 TCP → 8.8.4.4:53（DNS over TCP）；Trojan UDP 帧格式：
 *   atype(1) | addr | port(2) | len(2) | CRLF(2) | payload
 */
import type { RequestContext } from '../context';
import { TunnelError } from '../errors';
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../utils/bytes';
import { createRequestTcpConnector, type TcpConnector, type TcpSocket } from './dialer';
import { connectStreams } from './streams';
import type { ClientLikeSocket } from './grain';

/** DNS 响应包装器：明文 DNS 响应 → 客户端帧（Trojan 用；原 responseWrapper） */
export type DnsResponseWrapper = (chunk: Uint8Array) => Uint8Array | Uint8Array[];

/** Trojan UDP 会话上下文（原 trojanUdpCtx） */
export interface TrojanUdpCtx {
  cache: Uint8Array;
  proxyAddr: { hostname: string; port: number } | null;
  targetHost?: string;
  targetPort?: number;
  proxySocket?: TcpSocket | null;
}

export function createTrojanUdpCtx(proxyAddr: { hostname: string; port: number } | null): TrojanUdpCtx {
  return { cache: new Uint8Array(0), proxyAddr };
}

/**
 * DNS over TCP 转发（原 forwardataudp）：
 * 写查询 → 读响应 → 可选 wrapper 分帧 → 经 client 发回（首个分片前置 vlessHeader）。
 */
export async function forwardDnsTcp(
  ctx: RequestContext,
  udpChunk: Uint8Array | ArrayBuffer | ArrayBufferView,
  client: ClientLikeSocket,
  respHeader: Uint8Array | null,
  request: Request | null,
  responseWrapper: DnsResponseWrapper | null = null,
  tcpConnect?: TcpConnector,
): Promise<void> {
  const requestData = toUint8Array(udpChunk);
  const requestByteCount = requestData.byteLength;
  ctx.log('[UDP转发]', `收到 DNS 请求: ${requestByteCount}B -> 8.8.4.4:53`);
  try {
    const connect = tcpConnect ?? createRequestTcpConnector(request);
    const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
    let vlessHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(requestData);
    ctx.log('[UDP转发]', `DNS 请求已写入上游: ${requestByteCount}B`);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(
      new WritableStream<Uint8Array>({
        async write(chunk) {
          const rawResponse = toUint8Array(chunk);
          ctx.log('[UDP转发]', `收到 DNS 响应: ${rawResponse.byteLength}B`);
          const wrappedResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
          const sendFragments = Array.isArray(wrappedResult) ? wrappedResult : [wrappedResult];
          if (!sendFragments.length) return;
          if (client.readyState !== 1) return;
          for (const fragment of sendFragments) {
            const forwardResponse = toUint8Array(fragment);
            if (!forwardResponse.byteLength) continue;
            if (vlessHeader) {
              const response = new Uint8Array(vlessHeader.length + forwardResponse.byteLength);
              response.set(vlessHeader, 0);
              response.set(forwardResponse, vlessHeader.length);
              client.send(response);
              vlessHeader = null;
            } else {
              client.send(forwardResponse);
            }
          }
        },
      }),
    );
  } catch (error) {
    ctx.log('[UDP转发]', `DNS 转发失败: ${(error as Error)?.message || error}`);
  }
}

/**
 * Trojan UDP 帧解析 + DNS 转发（原 forwardTrojanUdp）。
 * 无 proxyAddr 时本地解析 Trojan UDP 帧 → 仅放行 port 53 → TCP DNS → 回帧。
 * 有 proxyAddr 时转 forwardTrojanUdpProxy（整条 TCP 隧道透传）。
 */
export async function forwardTrojanUdp(
  ctx: RequestContext,
  chunk: Uint8Array | ArrayBuffer | ArrayBufferView,
  client: ClientLikeSocket,
  trojanCtx: TrojanUdpCtx,
  request: Request | null,
  tcpConnect?: TcpConnector,
): Promise<void> {
  const currentChunk = toUint8Array(chunk);
  if (trojanCtx?.proxyAddr) {
    await forwardTrojanUdpProxy(ctx, currentChunk, client, trojanCtx, request, tcpConnect);
    return;
  }
  const cachedChunk = trojanCtx?.cache instanceof Uint8Array ? trojanCtx.cache : new Uint8Array(0);
  const input = cachedChunk.byteLength ? concatByteChunks(cachedChunk, currentChunk) : currentChunk;
  let cursor = 0;

  while (cursor < input.byteLength) {
    const packetStart = cursor;
    const atype = input[cursor];
    let addrCursor = cursor + 1;
    let addrLen = 0;
    if (atype === 1) addrLen = 4;
    else if (atype === 4) addrLen = 16;
    else if (atype === 3) {
      if (input.byteLength < addrCursor + 1) break;
      addrLen = 1 + input[addrCursor]!;
    } else throw new TunnelError('PROTOCOL_TROJAN_UDP_ADDR', `invalid trojan udp addressType: ${atype}`);

    const portCursor = addrCursor + addrLen;
    if (input.byteLength < portCursor + 6) break;

    const port = (input[portCursor]! << 8) | input[portCursor + 1]!;
    const payloadLength = (input[portCursor + 2]! << 8) | input[portCursor + 3]!;
    if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) {
      throw new TunnelError('PROTOCOL_TROJAN_UDP_DELIMITER', 'invalid trojan udp delimiter');
    }

    const payloadStart = portCursor + 6;
    const payloadEnd = payloadStart + payloadLength;
    if (input.byteLength < payloadEnd) break;

    const addrPortHeader = input.slice(packetStart, portCursor + 2);
    const payload = input.slice(payloadStart, payloadEnd);
    cursor = payloadEnd;

    if (port !== 53) throw new TunnelError('FORWARD_UDP_UNSUPPORTED', 'UDP is not supported');
    if (!payload.byteLength) continue;

    // UDP payload → TCP DNS 长度前缀（缺失则补 2 字节长度头）
    let tcpDnsQuery = payload;
    if (payload.byteLength < 2 || ((payload[0]! << 8) | payload[1]!) !== payload.byteLength - 2) {
      tcpDnsQuery = new Uint8Array(payload.byteLength + 2);
      tcpDnsQuery[0] = (payload.byteLength >>> 8) & 0xff;
      tcpDnsQuery[1] = payload.byteLength & 0xff;
      tcpDnsQuery.set(payload, 2);
    }

    const dnsResponseCtx = { cache: new Uint8Array(0) };
    await forwardDnsTcp(
      ctx,
      tcpDnsQuery,
      client,
      null,
      request,
      (dnsRespChunk) => {
        const currentResponseChunk = toUint8Array(dnsRespChunk);
        const responseInput = dnsResponseCtx.cache.byteLength
          ? concatByteChunks(dnsResponseCtx.cache, currentResponseChunk)
          : currentResponseChunk;
        const responseFrames: Uint8Array[] = [];
        let responseCursor = 0;
        while (responseCursor + 2 <= responseInput.byteLength) {
          const dnsLen = (responseInput[responseCursor]! << 8) | responseInput[responseCursor + 1]!;
          const dnsStart = responseCursor + 2;
          const dnsEnd = dnsStart + dnsLen;
          if (dnsEnd > responseInput.byteLength) break;
          const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
          const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
          frame.set(addrPortHeader, 0);
          frame[addrPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
          frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
          frame[addrPortHeader.byteLength + 2] = 0x0d;
          frame[addrPortHeader.byteLength + 3] = 0x0a;
          frame.set(dnsPayload, addrPortHeader.byteLength + 4);
          responseFrames.push(frame);
          responseCursor = dnsEnd;
        }
        dnsResponseCtx.cache = responseInput.slice(responseCursor);
        return responseFrames.length ? responseFrames : new Uint8Array(0);
      },
      tcpConnect,
    );
  }

  if (trojanCtx) trojanCtx.cache = input.slice(cursor);
}

/**
 * Trojan UDP 经反代地址的 TCP 隧道透传（原 forwardTrojanUdpProxy）：
 * 首包建立隧道并 connectStreams 对拷；后续写入隧道。
 */
export async function forwardTrojanUdpProxy(
  ctx: RequestContext,
  chunk: Uint8Array,
  client: ClientLikeSocket,
  trojanCtx: TrojanUdpCtx,
  request: Request | null,
  tcpConnect?: TcpConnector,
): Promise<void> {
  const data = toUint8Array(chunk);
  if (!trojanCtx.proxySocket) {
    const connect = tcpConnect ?? createRequestTcpConnector(request);
    const socket = connect({ hostname: stripBrackets(trojanCtx.proxyAddr!.hostname), port: trojanCtx.proxyAddr!.port });
    if (socket.opened) await socket.opened;
    if (effectiveByteLength(data) > 0) {
      const writer = socket.writable.getWriter();
      try {
        await writer.write(data);
      } finally {
        try {
          writer.releaseLock();
        } catch {
          /* ignore */
        }
      }
    }
    trojanCtx.proxySocket = socket;
    try {
      void socket.closed?.catch?.(() => {}).finally(() => closeQuiet(client));
    } catch {
      /* ignore */
    }
    void connectStreams(socket, client, null, null);
    return;
  }
  if (!data.byteLength) return;
  const writer = trojanCtx.proxySocket.writable.getWriter();
  try {
    await writer.write(data);
  } finally {
    try {
      writer.releaseLock();
    } catch {
      /* ignore */
    }
  }
}

function stripBrackets(hostname: string): string {
  const host = String(hostname || '').trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function closeQuiet(socket: ClientLikeSocket): void {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) socket.close?.();
  } catch {
    /* ignore */
  }
}
