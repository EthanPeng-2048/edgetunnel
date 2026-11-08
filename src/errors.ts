/**
 * 类型化错误 + 分层错误码（DESIGN.md §4.7）。
 *
 * 命名空间：TRANSPORT_* / PROTOCOL_* / FORWARD_* / CHAIN_* / CONFIG_* / AUTH_* / PLUGIN_*。
 * 约定：模块内只抛 TunnelError；Router 统一捕获、记日志、转响应。
 */
export class TunnelError extends Error {
  readonly code: string;

  constructor(code: string, message: string, cause?: unknown) {
    super(message, { cause });
    this.name = 'TunnelError';
    this.code = code;
  }
}
