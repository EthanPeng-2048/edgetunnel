/**
 * HTTPS 链式代理（原 _worker.js httpsConnect 分派 + TlsClient 握手，行为等价移植）。
 *
 * 原分派逻辑（forwardataTCP L2413-2415）：
 *   主机名为 IP 字面量 → 自研 TLS（fetcher secureTransport 需 SNI，IP 不适配）；
 *   否则 → httpConnect(httpsProxy=true) 即 fetcher secureTransport。
 * 此处统一收进 HttpsProvider.dial，调用方无需分支。
 */
import { ChainProvider, type ChainDialParams, type ChainDialResult } from './base';
import { TunnelError } from '../errors';
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../utils/bytes';
import { isIPHostname, stripIPv6Brackets } from '../utils/net';
import { httpConnectCore } from './http';
import { TlsClient, type TlsSocketLike } from './tls/client';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export class HttpsProvider extends ChainProvider {
  readonly name = 'https';

  async dial(params: ChainDialParams): Promise<ChainDialResult> {
    if (!isIPHostname(params.proxy.hostname)) {
      // 非 IP → fetcher secureTransport（原 httpConnect(..., true, ...)）
      return httpConnectCore(params, true);
    }
    return httpsConnectViaTlsClient(params);
  }
}

/** IP 字面量代理：自研 TLS 后 CONNECT（原 httpsConnect） */
async function httpsConnectViaTlsClient(params: ChainDialParams): Promise<ChainDialResult> {
  const { proxy, target, initialData, tcpConnect } = params;
  const { username, password, hostname, port } = proxy;
  const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
  let tlsSocket: TlsClient | null = null;

  const openHttpsProxyTls = async (allowChacha = false): Promise<TlsClient> => {
    const proxySocket = tcpConnect({ hostname, port });
    try {
      await proxySocket.opened;
      const socket = new TlsClient(proxySocket as TlsSocketLike, { serverName: tlsServerName, insecure: true, allowChacha });
      await socket.handshake();
      return socket;
    } catch (error) {
      try {
        proxySocket.close?.();
      } catch {
        /* ignore */
      }
      throw error;
    }
  };

  try {
    try {
      tlsSocket = await openHttpsProxyTls(false);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(msg)) throw error;
      tlsSocket = await openHttpsProxyTls(true);
    }

    const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
    const request =
      `CONNECT ${target.host}:${target.port} HTTP/1.1\r\n` +
      `Host: ${target.host}:${target.port}\r\n` +
      `${auth}User-Agent: Mozilla/5.0\r\n` +
      `Connection: keep-alive\r\n\r\n`;
    await tlsSocket!.write(textEncoder.encode(request));

    let responseBuffer: Uint8Array = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const value = await tlsSocket!.read();
      if (!value) throw new TunnelError('CHAIN_HTTPS_CONNECT', 'HTTPS 代理在返回 CONNECT 响应前关闭连接');
      responseBuffer = concatByteChunks(responseBuffer, value);
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

    if (headerEndIndex === -1) throw new TunnelError('CHAIN_HTTPS_CONNECT', 'HTTPS 代理 CONNECT 响应头过长或无效');
    const statusMatch = textDecoder.decode(responseBuffer.subarray(0, headerEndIndex)).split('\r\n')[0]!.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1]!, 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new TunnelError('CHAIN_HTTPS_CONNECT', `Connection failed: HTTP ${statusCode}`);
    }

    if (effectiveByteLength(initialData) > 0) await tlsSocket!.write(toUint8Array(initialData));
    const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
    let closedSettled = false;
    let resolveClosed!: () => void;
    let rejectClosed!: (e: unknown) => void;
    const closed = new Promise<void>((resolve, reject) => {
      resolveClosed = resolve;
      rejectClosed = reject;
    });
    const settleClosed = (settle: () => void, value?: unknown) => {
      if (!closedSettled) {
        closedSettled = true;
        if (value !== undefined) rejectClosed(value);
        else settle();
      }
    };
    const close = () => {
      try {
        tlsSocket!.close();
      } catch {
        /* ignore */
      }
      settleClosed(resolveClosed);
    };
    const readable = new ReadableStream<Uint8Array>({
      async start(controller) {
        try {
          if (bufferedData && bufferedData.byteLength > 0) controller.enqueue(bufferedData);
          for (;;) {
            const data = await tlsSocket!.read();
            if (!data) break;
            if (data.byteLength > 0) controller.enqueue(data);
          }
          try {
            controller.close();
          } catch {
            /* ignore */
          }
          settleClosed(resolveClosed);
        } catch (error) {
          try {
            controller.error(error);
          } catch {
            /* ignore */
          }
          settleClosed(resolveClosed, error);
        }
      },
      cancel() {
        close();
      },
    });
    const writable = new WritableStream<Uint8Array>({
      async write(chunk) {
        await tlsSocket!.write(toUint8Array(chunk));
      },
      close,
      abort(error) {
        close();
        if (error) settleClosed(resolveClosed, error);
      },
    });
    return {
      socket: { readable, writable, closed, close },
    };
  } catch (error) {
    try {
      tlsSocket?.close();
    } catch {
      /* ignore */
    }
    throw error;
  }
}
