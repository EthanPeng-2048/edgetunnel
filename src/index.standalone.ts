/**
 * 单文件打包入口（`npm run build` → dist/_worker.js）：
 * 供 Cloudflare 控制台粘贴、Pages 高级模式（构建输出根的 _worker.js）等
 * 无 [assets] 绑定或绑定不含页面文件的部署环境使用。
 *
 * 与 src/index.ts 的唯一差别：ASSETS 恒定替换为组合读取器——四个页面优先走
 * 内嵌副本（pages-embed），其余路径透传真实 ASSETS（若有）。
 * 注意：无 KV 时仍需配置变量 UUID（与原版 noKV 门禁一致）。
 */
import type { Env } from './env';
import worker from './index';
import { createStandaloneFetcher } from './pages-embed';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const effectiveEnv: Env = {
      ...env,
      ASSETS: { fetch: createStandaloneFetcher(env.ASSETS) } as Fetcher,
    };
    return worker.fetch(request, effectiveEnv, ctx);
  },
} satisfies ExportedHandler<Env>;
