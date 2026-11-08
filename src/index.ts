/**
 * xtunnel —— Cloudflare Worker 入口（DESIGN.md §3、§5）。
 *
 * 传输层：WebSocket、gRPC、xHTTP；协议：VLESS / Trojan / Shadowsocks；
 * 出站：直连 / ProxyIP 反代 / SOCKS5·HTTP·HTTPS·TURN·SSTP 链式代理。
 * 插件：订阅 / 优选 / 管理 API / 伪装页（plugins/*，启动期注册于 plugins/setup）。
 *
 * 迁移进度见 DESIGN.md §10：P0–P7 已完成；剩 P8 收尾（对照物归档、README、部署由用户决定）。
 */
import { RequestContext } from './context';
import { handleHttpRoute } from './router';
import type { Env } from './env';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const rctx = new RequestContext(request, env, ctx);

    try {
      // 1. HTTP 路由（核心路由表 → 插件链 → 兜底，P0 只有页面路由）
      const pageResponse = await handleHttpRoute(rctx);
      if (pageResponse) return pageResponse;

      // 3. 代理链路（Transport 评分选择 → Protocol → Forwarder）—— P4/P5 接入
      // 4. 未匹配 → 静态资源直落（run_worker_first 下的 assets 兜底）
      const assetResponse = await env.ASSETS?.fetch(request);
      if (assetResponse?.ok) return assetResponse;

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      // 统一错误出口（DESIGN.md §4.7）：始终输出 requestId 链路，错误码细化随 P3+
      rctx.error('entry', err instanceof Error ? err.message : String(err), err);
      return new Response('Internal Error', { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
