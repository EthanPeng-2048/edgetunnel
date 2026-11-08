/**
 * 请求日志（DESIGN.md §4.7）。
 *
 * 原实现是模块级 `debugLogging` + 自由 `log()`（并发请求共享开关）。
 * 现在开关挂在 RequestContext（每请求），这里只提供格式化与输出。
 */
import type { RequestContext } from '../context';

/** 模块内日志：自动带上 requestId 与模块名 */
export function moduleLog(rctx: RequestContext, module: string, ...args: unknown[]): void {
  rctx.log(module, ...args);
}

/**
 * 原 log() 的 debug 开关语义：仅 DEBUG 打开时输出。
 * RequestContext.log 已按 debug 分流，这里保留给非请求上下文的启动期日志。
 */
export function startupLog(debug: boolean, ...args: unknown[]): void {
  if (debug) console.log(...args);
}
