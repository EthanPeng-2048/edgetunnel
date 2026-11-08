/**
 * 内嵌页面兜底（单文件上传 / Pages 高级模式用）：把 assets/pages/*.html 打进 bundle，
 * 作为资源读取的**第一优先级**，未命中的路径再回落真实 ASSETS 绑定（无绑定则 404）。
 * 适配三种环境：Workers 无 ASSETS（控制台粘贴）、Pages 高级模式（ASSETS 可能缺失或
 * 不含页面文件）、wrangler deploy 正常路径（内嵌与 assets 同源，行为一致）。
 * 正常 wrangler deploy 的页面仍随 assets 上传，本模块只是入口包内的确定性兜底。
 */
import loginHtml from '../assets/pages/login.html';
import adminHtml from '../assets/pages/admin.html';
import noAdminHtml from '../assets/pages/noADMIN.html';
import noKvHtml from '../assets/pages/noKV.html';

const PAGES: Record<string, string> = {
  '/pages/login.html': loginHtml,
  '/pages/admin.html': adminHtml,
  '/pages/noADMIN.html': noAdminHtml,
  '/pages/noKV.html': noKvHtml,
};

/** 组合资源读取器：签名与 ASSETS.fetch 一致；四个页面恒定走内嵌，其余透传 real */
export function createStandaloneFetcher(real?: Fetcher) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const { pathname } = new URL(request.url);
    const html = PAGES[pathname];
    if (html !== undefined) {
      return new Response(html, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
    if (real) return real.fetch(request);
    return new Response('Not Found', { status: 404 });
  };
}
