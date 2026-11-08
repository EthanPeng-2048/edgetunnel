/**
 * 单文件打包入口（`npm run build` → dist/_worker.js）：
 * 供 Cloudflare 控制台粘贴 / 单文件上传测试使用。
 *
 * 与 src/index.ts 的唯一差别：ASSETS 未绑定时用内嵌页面（pages-embed）
 * 顶上，使 /login /admin /noADMIN /noKV 在纯 Worker 部署下可用。
 * 注意：无 KV 时仍需在控制台设置变量 UUID（与原版 noKV 门禁一致）。
 */
import type { Env } from './env';
import worker from './index';
import { embeddedAssetsFetch } from './pages-embed';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const effectiveEnv: Env = env.ASSETS
      ? env
      : { ...env, ASSETS: { fetch: embeddedAssetsFetch } as Fetcher };
    return worker.fetch(request, effectiveEnv, ctx);
  },
} satisfies ExportedHandler<Env>;
