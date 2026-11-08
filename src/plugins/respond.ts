/**
 * 插件共用的响应构造小工具（避免插件 ↔ router 循环依赖）。
 */

const JSON_UTF8 = 'application/json;charset=utf-8';

/** JSON 响应（pretty 时缩进 2 空格，与原实现 JSON.stringify(x, null, 2) 一致） */
export function jsonResponse(data: unknown, status = 200, pretty = true, contentType: string = JSON_UTF8): Response {
  return new Response(pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data), {
    status,
    headers: { 'Content-Type': contentType },
  });
}

/** 统一重定向体（原「重定向中...」） */
export function redirectResponse(location: string, status = 302): Response {
  return new Response('重定向中...', { status, headers: { 'Location': location } });
}
