/**
 * 内嵌页面兜底（单文件上传用）：把 assets/pages/*.html 打进 bundle，
 * 在 ASSETS 绑定缺失时（如控制台粘贴部署）替代 Static Assets 提供登录/管理页。
 * 正常 wrangler deploy 路径不引用本模块，页面仍走 ASSETS（DESIGN.md D1 不变）。
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

/** 接口与 ASSETS.fetch 一致：命中返回 200 HTML，未命中 404（由入口落 404 兜底） */
export async function embeddedAssetsFetch(request: Request): Promise<Response> {
  const { pathname } = new URL(request.url);
  const html = PAGES[pathname];
  if (html === undefined) return new Response('Not Found', { status: 404 });
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
