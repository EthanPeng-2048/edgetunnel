/**
 * 传输层基类（DESIGN.md §4.2）。
 *
 * 职责边界：HTTP 帧 ↔ 双向字节流（升级 / 成帧 / early data / padding）。
 * 传输层不理解协议语义 —— 首包嗅探与解析由 Protocol 层完成（见 protocol/base.ts）。
 *
 * 统一契约：score() 评分选传输 → accept() 建会话 → respond() 出 HTTP 响应。
 * 新增传输 = 新子类 + 注册表注册，Router 零改动。
 */
import type { RequestContext } from '../context';

/** 已建立的双向字节流会话（每请求一实例） */
export interface TransportSession {
  readonly name: string;
  /** 客户端 → 边缘（传输层已解帧；WS 含 earlyData 注入流首部） */
  readonly readable: ReadableStream<Uint8Array>;
  /** 边缘 → 客户端（写入时由传输层成帧） */
  readonly writable: WritableStream<Uint8Array>;
  /** 传输层已解码的带外首段字节（WS 的 sec-websocket-protocol early data）——
   * 不在 readable 中；编排器以其为协议嗅探起点，再从 readable 续读。
   * gRPC/xHTTP 无带外数据，恒为 undefined（首包从 readable 读）。 */
  readonly earlyData?: Uint8Array;
  close(reason?: string): void;
}

/** accept() 的结果：成功建会话，或传输层直接拒绝（如 xHTTP padding 校验失败 400） */
export type TransportAccept =
  | { ok: true; session: TransportSession; respond(opts?: RespondOptions): Response }
  | { ok: false; response: Response };

/**
 * respond() 可选参数 —— 早期短路响应（编排器在协议解析后判定测速/UDP 拒绝时使用）。
 * 仅 xHTTP 用得上（原 L628-641 的独立 Response）；WS/gRPC 的测速数据走会话流，忽略此参数。
 */
export interface RespondOptions {
  /** 短路响应体（如 buildLocal204Response 的字节、错误文案） */
  localBody?: BodyInit;
  /** 短路响应状态码（默认 200） */
  status?: number;
  /** 短路响应头（默认无） */
  headers?: HeadersInit;
}

export abstract class Transport {
  abstract readonly name: string;

  /**
   * 请求评分：0 = 不匹配；分高者胜，同分先注册。
   * 约定分档：WS=100（Upgrade: websocket）、gRPC=80（POST+content-type+无 xHTTP 信号）、
   * xHTTP=60（POST 兜底）。全部要求 adminPassword（原 L89/L93 条件）。
   */
  abstract score(request: Request, ctx: RequestContext): number;

  /** 建立会话（HTTP 升级/流初始化 + 帧层准备）；失败返回 { ok:false, response } */
  abstract accept(request: Request, ctx: RequestContext): Promise<TransportAccept>;
}
