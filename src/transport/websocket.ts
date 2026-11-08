/**
 * WebSocket 传输（原 handleWsRequest 的帧层部分，行为等价移植）。
 *
 * 移植边界：WebSocketPair 升级、sec-websocket-protocol early data 解码/校验、
 * message 事件 ↔ 字节流。上行合包队列 / Grain 下行 / 测速模式 / 协议分发属 P5 转发核心。
 */
import { Transport, type TransportAccept } from './base';
import type { RequestContext } from '../context';
import { toUint8Array } from '../utils/bytes';
import { uuidBytesMatch } from '../utils/uuid-bytes';
import { sha224 } from '../utils/sha224';

const WS_EARLY_DATA_MAX_BYTES = 8 * 1024;
const WS_EARLY_DATA_MAX_HEADER = Math.ceil((WS_EARLY_DATA_MAX_BYTES * 4) / 3) + 4;

/** early data 是否像合法首包（VLESS UUID 或 Trojan SHA224 头）—— 原 isValidWsEarlyData */
export function isValidWsEarlyData(bytes: Uint8Array, token: string): boolean {
  if (!bytes?.byteLength) return false;
  if (bytes.byteLength >= 18 && uuidBytesMatch(bytes, 1, token)) return true;
  if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

  const trojanPassword = sha224(token);
  for (let i = 0; i < 56; i++) {
    if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
  }
  return true;
}

/** 解码 sec-websocket-protocol 中的 base64url early data —— 原 decodeWsEarlyData */
export function decodeWsEarlyData(header: string, token: string): Uint8Array | null {
  if (!header) return null;
  if (header.length > WS_EARLY_DATA_MAX_HEADER) throw new Error('early data is too large');

  let bytes: Uint8Array | undefined;
  const Uint8ArrayBase64 = Uint8Array as unknown as {
    fromBase64?(s: string, opts?: { alphabet?: string }): Uint8Array;
  };
  if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
    try {
      bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
    } catch {
      // 回退到手动解码
    }
  }
  if (!bytes) {
    let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    if (padding) normalized += '='.repeat(4 - padding);
    let binaryString: string;
    try {
      binaryString = atob(normalized);
    } catch {
      return null;
    }
    bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  }

  if (bytes.byteLength > WS_EARLY_DATA_MAX_BYTES) throw new Error('early data is too large');
  return isValidWsEarlyData(bytes, token) ? bytes : null;
}

export class WebSocketTransport extends Transport {
  readonly name = 'websocket';

  override score(request: Request, ctx: RequestContext): number {
    if (!ctx.adminPassword) return 0;
    const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
    return upgrade === 'websocket' ? 100 : 0;
  }

  override async accept(request: Request, ctx: RequestContext): Promise<TransportAccept> {
    const wsSocketPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wsSocketPair) as [WebSocket, WebSocket];
    try {
      // 原 L1318：优先带 allowHalfOpen 的新版 accept，失败回退无参（CF 运行时版本差异）
      (serverSock as unknown as { accept(opts?: { allowHalfOpen?: boolean }): void }).accept({ allowHalfOpen: true });
    } catch {
      serverSock.accept();
    }
    serverSock.binaryType = 'arraybuffer';

    // early data（?enc= 存在时禁用 —— 原 ssModeDisableEarlyData，避免把子协议值误当 SS 数据）
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const ssModeDisableEarlyData = !!ctx.url.searchParams.get('enc');
    let earlyData: Uint8Array | undefined;
    if (!ssModeDisableEarlyData && earlyDataHeader) {
      try {
        const decoded = decodeWsEarlyData(earlyDataHeader, ctx.userId);
        if (decoded?.byteLength) earlyData = decoded;
      } catch (err) {
        // 原 handleWsTransferError：early data 过大 → 关闭连接
        try {
          serverSock.close(1009, 'early data is too large');
        } catch {
          /* ignore */
        }
        return { ok: false, response: new Response('early data is too large', { status: 400 }) };
      }
    }

    // message 事件 → readable 流
    let readableController!: ReadableStreamDefaultController<Uint8Array>;
    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        readableController = controller;
      },
    });
    serverSock.addEventListener('message', (event: MessageEvent) => {
      const chunk = toUint8Array(event.data);
      if (chunk.byteLength > 0) readableController.enqueue(chunk);
    });
    serverSock.addEventListener('close', () => {
      try {
        readableController.close();
      } catch {
        /* already closed */
      }
    });
    serverSock.addEventListener('error', (err: unknown) => {
      try {
        readableController.error(err);
      } catch {
        /* already closed */
      }
    });

    // writable → serverSock.send()
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        serverSock.send(chunk);
      },
      close() {
        try {
          serverSock.close();
        } catch {
          /* ignore */
        }
      },
      abort() {
        try {
          serverSock.close();
        } catch {
          /* ignore */
        }
      },
    });

    const session = {
      name: this.name,
      readable,
      writable,
      earlyData,
      close(reason?: string) {
        try {
          serverSock.close(1000, reason);
        } catch {
          /* ignore */
        }
        try {
          readableController.close();
        } catch {
          /* ignore */
        }
      },
    };

    return {
      ok: true,
      session,
      // 原 L1811：101 升级响应，禁用扩展协商（避免 permessage-deflate 干扰）
      respond() {
        return new Response(null, {
          status: 101,
          webSocket: clientSock,
          headers: { 'Sec-WebSocket-Extensions': '' },
        } as ResponseInit & { webSocket: WebSocket });
      },
    };
  }
}
