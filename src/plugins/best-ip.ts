/**
 * 优选插件（DESIGN.md §4.5；原 _worker.js L143 getADDAPI + L518 locations）。
 *
 * 认领路径：
 * - `admin/getADDAPI`（大小写敏感，与原 caseSensitivePath 一致）：验证优选 API，
 *   cookie 门禁在本插件内做（原 admin 分支 L131 门禁的等价前移）；
 * - `locations`（cookie 有效才代理 speed.cloudflare.com/locations，
 *   无效返回 null 落伪装页 —— 与原 L518-521 无 return 的落链行为一致）。
 *
 * 随机 IP 池 / 优选 API 抓取的实现在 services/bestip.ts（订阅与 admin/ADD.txt 复用）。
 */
import type { RequestContext } from '../context';
import { verifyAuthCookie } from '../auth';
import { fetchBestIPApi } from '../services/bestip';
import { Plugin } from './base';
import { jsonResponse, redirectResponse } from './respond';

export class BestIpPlugin extends Plugin {
  readonly name = 'best-ip';

  override async onRoute(rctx: RequestContext): Promise<Response | null> {
    const caseSensitivePath = rctx.url.pathname.slice(1);
    const requestPath = caseSensitivePath.toLowerCase();

    if (caseSensitivePath === 'admin/getADDAPI') return this.handleVerifyApi(rctx);
    if (requestPath === 'locations') return this.handleLocations(rctx);
    return null;
  }

  /** L143-157：验证优选 API（admin cookie 门禁 → 拉取解析 → JSON 结果） */
  private async handleVerifyApi(rctx: RequestContext): Promise<Response> {
    const { request, url } = rctx;
    // 原 L131 admin 分支 cookie 门禁（无效 → /login）
    if (!(await verifyAuthCookie(request, rctx.encryptionSecret, rctx.adminPassword!))) {
      return redirectResponse('/login');
    }

    const bestIPUrlsToVerify = url.searchParams.get('url');
    if (bestIPUrlsToVerify) {
      try {
        new URL(bestIPUrlsToVerify);
        const bestIPApiContent = await fetchBestIPApi([bestIPUrlsToVerify], url.searchParams.get('port') || '443', rctx.identity[0]);
        let bestIPApiResults = bestIPApiContent[0].length > 0 ? bestIPApiContent[0] : bestIPApiContent[1];
        bestIPApiResults = bestIPApiResults.map((item) => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
        return jsonResponse({ success: true, data: bestIPApiResults }, 200, true);
      } catch (err) {
        const error = err as Error;
        return jsonResponse({ msg: '验证优选API失败，失败原因：' + error.message, error: error.message }, 500, true);
      }
    }
    return jsonResponse({ success: false, data: [] }, 403, true);
  }

  /** L518-521：反代 locations 列表（cookie 有效才代理，否则 null 落伪装页） */
  private async handleLocations(rctx: RequestContext): Promise<Response | null> {
    if (await verifyAuthCookie(rctx.request, rctx.encryptionSecret, rctx.adminPassword!)) {
      return fetch(
        new Request('https://speed.cloudflare.com/locations', {
          headers: { Referer: 'https://speed.cloudflare.com/' },
        }),
      );
    }
    return null;
  }
}
