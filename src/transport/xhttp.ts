/**
 * xHTTP 传输（原 handleXhttpRequest 的帧层部分，行为等价移植）。
 *
 * 移植边界：HPACK padding 校验、身份头生成、request.body ↔ 流式响应。
 * 首包读取/协议解析/测速判定/UDP 桥属协议层与 P5 编排（原 readXhttpFirstPacket 内联了
 * 协议解析，重构后由编排器从 session.readable 读字节 → Protocol.sniff/parse）。
 */
import { Transport, type TransportAccept } from './base';
import type { RequestContext } from '../context';
import { getIdentity } from '../services/identity';
import { HPACK_HUFFMAN_CODE_LENGTHS } from './hpack';

const XHTTP_BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** padding 值的 HPACK Huffman 编码字节长度 —— 原 calcHpackHuffmanByteLength */
export function calcHpackHuffmanByteLength(str: string): number {
  const bytes = new TextEncoder().encode(str);
  let totalBits = 0;
  for (let i = 0; i < bytes.length; i++) {
    totalBits += HPACK_HUFFMAN_CODE_LENGTHS[bytes[i]!]!;
  }
  return Math.ceil(totalBits / 8);
}

/** 从请求头或查询参数提取 padding 值 —— 原 extractXhttpPaddingValue */
export function extractXhttpPaddingValue(request: Request, identityHeader: string, identityKey: string): string {
  const headerValue = request.headers.get(identityHeader);
  if (headerValue) {
    try {
      const parseUrl = new URL(headerValue, 'https://x.invalid');
      const queryValue = parseUrl.searchParams.get(identityKey);
      if (queryValue) return queryValue;
    } catch {
      // 非 URL 形态 → 用原值
    }
    return headerValue;
  }
  const requestUrl = new URL(request.url);
  return requestUrl.searchParams.get(identityKey) || '';
}

/** padding 校验：无 padding 放行；有则 HPACK Huffman 长度须在 [98, 1002] —— 原 verifyXhttpPadding */
export function verifyXhttpPadding(request: Request, identityHeader: string, identityKey: string): boolean {
  const paddingValue = extractXhttpPaddingValue(request, identityHeader, identityKey);
  if (!paddingValue) return true;
  const huffmanByteLen = calcHpackHuffmanByteLength(paddingValue);
  return huffmanByteLen >= 98 && huffmanByteLen <= 1002;
}

/** 生成 base62 随机 padding 串 —— 原 generateXhttpPaddingString */
export function generateXhttpPaddingString(length: number): string {
  const charsetLen = XHTTP_BASE62_ALPHABET.length;
  let result = '';
  for (let i = 0; i < length; i++) {
    result += XHTTP_BASE62_ALPHABET[Math.floor(Math.random() * charsetLen)]!;
  }
  return result;
}

export class XhttpTransport extends Transport {
  readonly name = 'xhttp';

  override score(request: Request, ctx: RequestContext): number {
    if (!ctx.adminPassword) return 0;
    if (request.method !== 'POST') return 0;
    const path = ctx.url.pathname.slice(1).toLowerCase();
    // 原 L93 只排除 admin/* 前缀与 login（注意：精确路径 /admin 不排除 —— 与原行为一致）
    if (path.startsWith('admin/') || path === 'login') return 0;
    // POST 兜底（原 L100 else 分支）：gRPC 以更高分 80 抢走其专属场景
    return 60;
  }

  override async accept(request: Request, ctx: RequestContext): Promise<TransportAccept> {
    if (!request.body) return { ok: false, response: new Response('Bad Request', { status: 400 }) };

    const [identityHeader, identityKey] = getIdentity(ctx.userId);
    if (!verifyXhttpPadding(request, identityHeader, identityKey)) {
      return { ok: false, response: new Response('Bad Request', { status: 400 }) };
    }

    // 上行：原样透传 HTTP body（xHTTP 无额外帧层）
    const readable = request.body;

    // 下行：写入 → 流式响应
    let downlinkController!: ReadableStreamDefaultController<Uint8Array>;
    const responseStream = new ReadableStream<Uint8Array>({
      start(controller) {
        downlinkController = controller;
      },
    });
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        downlinkController.enqueue(chunk);
      },
      close() {
        try {
          downlinkController.close();
        } catch {
          /* already closed */
        }
      },
      abort(reason) {
        try {
          downlinkController.error(reason);
        } catch {
          /* already closed */
        }
      },
    });

    // 身份头 padding（原 L650-654：随机 100..1000 字符）
    let identityHeaderValue = '';
    try {
      const responseUrl = new URL('https://x.invalid/');
      responseUrl.searchParams.set(identityKey, generateXhttpPaddingString(100 + Math.floor(Math.random() * 901)));
      identityHeaderValue = responseUrl.toString();
    } catch {
      // URL 构造失败 → 不带身份头（原 catch 空实现）
    }

    const streamingHeaders = new Headers({
      'Content-Type': 'application/octet-stream',
      'X-Accel-Buffering': 'no',
      'Cache-Control': 'no-store',
    });
    if (identityHeaderValue) streamingHeaders.set(identityHeader, identityHeaderValue);

    const session = {
      name: this.name,
      readable,
      writable,
      close(reason?: string) {
        try {
          downlinkController.close();
        } catch {
          /* ignore */
        }
        void reason;
      },
    };

    return {
      ok: true,
      session,
      respond(opts) {
        if (opts?.localBody !== undefined) {
          // 早期短路响应（测速 204 / UDP 拒绝等，原 L628-641）：不带身份头
          return new Response(opts.localBody, {
            status: opts.status ?? 200,
            headers: opts.headers,
          });
        }
        return new Response(responseStream, { status: 200, headers: streamingHeaders });
      },
    };
  }
}
