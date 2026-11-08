/**
 * HTTP/HTTPS CONNECT 链式代理（原 _worker.js httpConnect，行为等价移植）。
 *
 * httpsProxy=true 时用 fetcher 的 secureTransport:'on' 建 TLS（原非 IP 主机名路径）；
 * CONNECT 响应头后夹带的目标字节回灌到 readable，避免首包被吞。
 */
import { ChainProvider, type ChainDialParams, type ChainDialResult } from './base';
import { TunnelError } from '../errors';
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../utils/bytes';
import type { TcpSocket } from '../forward/dialer';

export class HttpProvider extends ChainProvider {
  readonly name = 'http';

  async dial(params: ChainDialParams): Promise<ChainDialResult> {
    return httpConnectCore(params, false);
  }
}

/** httpsProxy=true：fetcher secureTransport TLS 后再 CONNECT（原 httpConnect 第 4 参） */
export async function httpConnectCore(params: ChainDialParams, httpsProxy: boolean): Promise<ChainDialResult> {
  const { proxy, target, initialData, tcpConnect } = params;
  const { username, password, hostname, port } = proxy;
  const socket: TcpSocket = httpsProxy
    ? tcpConnect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
    : tcpConnect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  try {
    if (httpsProxy && socket.opened) await socket.opened;

    const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
    const request =
      `CONNECT ${target.host}:${target.port} HTTP/1.1\r\n` +
      `Host: ${target.host}:${target.port}\r\n` +
      `${auth}User-Agent: Mozilla/5.0\r\n` +
      `Connection: keep-alive\r\n\r\n`;
    await writer.write(encoder.encode(request));
    writer.releaseLock();

    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const { done, value } = await reader.read();
      if (done || !value) {
        throw new TunnelError('CHAIN_HTTP_CONNECT', `${httpsProxy ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
      }
      responseBuffer = new Uint8Array([...responseBuffer, ...value]);
      bytesRead = responseBuffer.byteLength;
      const crlfcrlf = responseBuffer.findIndex(
        (_, i) =>
          i < responseBuffer.byteLength - 3 &&
          responseBuffer[i] === 0x0d &&
          responseBuffer[i + 1] === 0x0a &&
          responseBuffer[i + 2] === 0x0d &&
          responseBuffer[i + 3] === 0x0a,
      );
      if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
    }

    if (headerEndIndex === -1) throw new TunnelError('CHAIN_HTTP_CONNECT', '代理 CONNECT 响应头过长或无效');
    const statusMatch = decoder.decode(responseBuffer.subarray(0, headerEndIndex)).split('\r\n')[0]!.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1]!, 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new TunnelError('CHAIN_HTTP_CONNECT', `Connection failed: HTTP ${statusCode}`);
    }

    reader.releaseLock();

    if (effectiveByteLength(initialData) > 0) {
      const remoteWriter = socket.writable.getWriter();
      await remoteWriter.write(toUint8Array(initialData));
      remoteWriter.releaseLock();
    }

    // CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞（原 L3243-3250）。
    // readableHighWaterMark 放宽：避免首块 write 在无消费者时被背压阻塞（Node 测试环境）。
    if (bytesRead > headerEndIndex) {
      const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>(undefined, { highWaterMark: 16 }, { highWaterMark: 16 });
      const transformWriter = writable.getWriter();
      await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
      transformWriter.releaseLock();
      void socket.readable.pipeTo(writable).catch(() => {});
      return {
        socket: {
          readable,
          writable: socket.writable,
          opened: socket.opened,
          closed: socket.closed,
          close: () => socket.close?.(),
        },
      };
    }

    return { socket };
  } catch (error) {
    try {
      writer.releaseLock();
    } catch {
      /* ignore */
    }
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
    try {
      socket.close?.();
    } catch {
      /* ignore */
    }
    throw error;
  }
}
