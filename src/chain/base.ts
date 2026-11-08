/**
 * 链式代理基类与注册表（DESIGN.md §4.4）。
 *
 * 五子类（SOCKS5 / HTTP / HTTPS+自研TLS / TURN / SSTP）统一 dial() 接口；
 * forwarder 按 proxyCtx.proxyType 查表调用，新增链式 = 新子类 + 注册。
 */
import { TunnelError } from '../errors';
import type { TcpConnector } from '../forward/dialer';

/** 代理端点（原 parsedSocks5 / ctxProxyParams） */
export interface ChainProxyEndpoint {
  hostname: string;
  port: number;
  username?: string;
  password?: string;
}

/** dial 入参（DESIGN.md §4.4） */
export interface ChainDialParams {
  proxy: ChainProxyEndpoint;
  target: { host: string; port: number };
  /** 协议首包；代理握手完成后随隧道发出（原 initialData） */
  initialData: Uint8Array | null;
  tcpConnect: TcpConnector;
}

/**
 * dial 出参。
 * socket：已完成代理握手、可直接读写到目标的连接（readable 已含握手期间先行到达的目标字节）。
 * —— 原实现中 http/https/turn/sstp 通过 TransformStream 或自建流把 head 拼进 readable，
 *    此处统一由子类自行拼好，调用方无需二次处理（与原 forwardataTCP 消费方式一致）。
 * 结构宽于 fetcher.Socket（opened 可选）：自研流式适配器（https/turn/sstp）无 opened。
 */
export interface ChainSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened?: Promise<unknown>;
  closed?: Promise<unknown>;
  close?(): void;
}

export interface ChainDialResult {
  socket: ChainSocket;
}

export abstract class ChainProvider {
  abstract readonly name: string;

  /** 建立经代理到目标的隧道；失败抛 TunnelError(CHAIN_*) */
  abstract dial(params: ChainDialParams): Promise<ChainDialResult>;
}

/** 链式代理注册表：proxyType 字符串 → Provider 实例 */
export class ChainRegistry {
  private readonly items = new Map<string, ChainProvider>();

  register(provider: ChainProvider): this {
    if (this.items.has(provider.name)) {
      throw new TunnelError('REGISTRY_DUPLICATE', `链式代理重名注册: ${provider.name}`);
    }
    this.items.set(provider.name, provider);
    return this;
  }

  get(type: string): ChainProvider | undefined {
    return this.items.get(type);
  }

  has(type: string): boolean {
    return this.items.has(type);
  }

  list(): ChainProvider[] {
    return [...this.items.values()];
  }
}

/** 统一超时（原 withTimeout；CONNECT_TIMEOUT_MS = 9999 见 dialer） */
export async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new TunnelError('CHAIN_TIMEOUT', message)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
