/**
 * gRPC 传输（原 handleGrpcRequest 的帧层部分，行为等价移植）。
 *
 * 移植边界：HTTP/2 gRPC 消息帧的编解码（5 字节头 + protobuf 包装）、
 * request.body ↔ 字节流、流式响应。上行写队列 / 连接世代 / 协议分发属 P5。
 *
 * 帧布局（gRPC over HTTP/2 message）：
 *   下行（发往客户端）：0x00 | len(4B BE) | 0x0a | varint(payloadLen) | payload
 *   上行（来自客户端）：0x00 | len(4B BE) | [0x0a | varint(payloadLen) |] payload
 *   —— 上行剥壳时容忍无 protobuf 包装的裸 payload（原实现语义）。
 */
import { Transport, type TransportAccept } from './base';
import type { RequestContext } from '../context';
import { concatByteChunks, toUint8Array } from '../utils/bytes';

const GRPC_RESPONSE_HEADERS = {
  'Content-Type': 'application/grpc',
  'grpc-status': '0',
  'X-Accel-Buffering': 'no',
  'Cache-Control': 'no-store',
} as const;

/** LEB128 varint 编码（7bit/字节，最高位为续位）—— 原 grpcBridge.send 内联逻辑 */
function encodeVarint(value: number): Uint8Array {
  const out: number[] = [];
  let remaining = value >>> 0;
  while (remaining > 127) {
    out.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  out.push(remaining);
  return new Uint8Array(out);
}

/** 下行：payload → gRPC 消息帧（原 grpcBridge.send 的 framing） */
export function buildGrpcFrame(payload: Uint8Array): Uint8Array {
  const varint = encodeVarint(payload.byteLength);
  const protobufLen = 1 + varint.length + payload.byteLength;
  const frame = new Uint8Array(5 + protobufLen);
  frame[0] = 0; // compressed flag
  frame[1] = (protobufLen >>> 24) & 0xff;
  frame[2] = (protobufLen >>> 16) & 0xff;
  frame[3] = (protobufLen >>> 8) & 0xff;
  frame[4] = protobufLen & 0xff;
  frame[5] = 0x0a; // protobuf field 1, length-delimited
  frame.set(varint, 6);
  frame.set(payload, 6 + varint.length);
  return frame;
}

/**
 * 上行帧解析器：累积字节流 → 逐帧剥壳。
 * 用法：push(chunk) 返回本批解出的 payload 列表（可能为空 —— 帧未齐）。
 * —— 原 handleGrpcRequest 的 pending 缓冲循环。
 */
export class GrpcFrameParser {
  private pending: Uint8Array = new Uint8Array(0);

  push(chunk: Uint8Array): Uint8Array[] {
    this.pending = concatByteChunks(this.pending, toUint8Array(chunk));
    const payloads: Uint8Array[] = [];
    while (this.pending.byteLength >= 5) {
      const grpcLen = ((this.pending[1]! << 24) >>> 0) | (this.pending[2]! << 16) | (this.pending[3]! << 8) | this.pending[4]!;
      const frameSize = 5 + grpcLen;
      if (this.pending.byteLength < frameSize) break;
      let payload = this.pending.subarray(5, frameSize);
      this.pending = this.pending.subarray(frameSize);
      if (!payload.byteLength) continue;

      // 剥 protobuf 包装：0x0a + varint 长度（原 L1176-1189，容忍裸 payload）
      if (payload.byteLength >= 2 && payload[0] === 0x0a) {
        let shift = 0;
        let offset = 1;
        let varintValid = false;
        while (offset < payload.length) {
          const current = payload[offset++]!;
          if ((current & 0x80) === 0) {
            varintValid = true;
            break;
          }
          shift += 7;
          if (shift > 35) break;
        }
        if (varintValid) payload = payload.subarray(offset);
      }
      if (!payload.byteLength) continue;
      payloads.push(payload);
    }
    return payloads;
  }
}

export class GrpcTransport extends Transport {
  readonly name = 'grpc';

  override score(request: Request, ctx: RequestContext): number {
    if (!ctx.adminPassword) return 0;
    if (request.method !== 'POST') return 0;
    const path = ctx.url.pathname.slice(1).toLowerCase();
    // 原 L93 只排除 admin/* 前缀与 login（注意：精确路径 /admin 不排除 —— 与原行为一致）
    if (path.startsWith('admin/') || path === 'login') return 0;
    const contentType = (request.headers.get('Content-Type') || '').toLowerCase();
    if (!contentType.startsWith('application/grpc')) return 0;
    // xHTTP 信号头/参数存在时归 xHTTP（原 L96 hitXhttpSignal 反向条件）
    const [identityHeader, identityKey] = ctx.identity;
    const hitXhttpSignal = !!request.headers.get(identityHeader) || !!ctx.url.searchParams.get(identityKey);
    if (hitXhttpSignal) return 0;
    return 80;
  }

  override async accept(request: Request, ctx: RequestContext): Promise<TransportAccept> {
    if (!request.body) return { ok: false, response: new Response('Bad Request', { status: 400 }) };
    void ctx;

    // 上行：request.body → 剥帧 → payload 字节流
    const parser = new GrpcFrameParser();
    const readable = request.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          for (const payload of parser.push(chunk)) controller.enqueue(payload);
        },
      }),
    );

    // 下行：payload → buildGrpcFrame → 流式响应
    let downlinkController!: ReadableStreamDefaultController<Uint8Array>;
    const responseStream = new ReadableStream<Uint8Array>({
      start(controller) {
        downlinkController = controller;
      },
    });
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        downlinkController.enqueue(buildGrpcFrame(toUint8Array(chunk)));
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
      respond() {
        return new Response(responseStream, { status: 200, headers: GRPC_RESPONSE_HEADERS });
      },
    };
  }
}
