/**
 * 认证（原 _worker.js 章节 2 的 cookie/密码校验，安全增强移植）。
 *
 * 兼容红线 #2：cookie = MD5MD5(UA + KEY + ADMIN)，算法不可变。
 * 安全增强：原实现用 `==`/`===` 直接比较（时序侧信道），这里统一走
 * timingSafeEqual 恒定时间比较（P1 验收项）。
 */
import { md5Md5 } from './services/md5';

/**
 * 恒定时间字符串比较。
 * 两侧都按 UTF-8 编码后逐字节 XOR 累积；长度不同也遍历到最长侧，
 * 不因长度或首个差异字节提前返回。
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bytesA = encoder.encode(a);
  const bytesB = encoder.encode(b);
  const maxLen = Math.max(bytesA.length, bytesB.length);
  // 长度差异也折叠进 diff，避免仅凭长度提前判断
  let diff = bytesA.length ^ bytesB.length;
  for (let i = 0; i < maxLen; i++) {
    diff |= (bytesA[i] ?? 0) ^ (bytesB[i] ?? 0);
  }
  return diff === 0;
}

/** 计算登录 cookie 期望值：MD5MD5(UA + KEY + ADMIN)（原算法原样） */
export function computeAuthCookie(ua: string, encryptionSecret: string, adminPassword: string): Promise<string> {
  return Promise.resolve(md5Md5(ua + encryptionSecret + adminPassword));
}

/** 从 Cookie 头提取 auth 值；无则返回 null */
export function extractAuthCookie(request: Request): string | null {
  const cookies = request.headers.get('Cookie') || '';
  const authCookie = cookies
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('auth='))
    ?.slice('auth='.length);
  return authCookie ?? null;
}

/** 校验 auth cookie 是否有效（恒定时间比较） */
export async function verifyAuthCookie(
  request: Request,
  encryptionSecret: string,
  adminPassword: string,
): Promise<boolean> {
  const authCookie = extractAuthCookie(request);
  if (!authCookie) return false;
  const expected = await computeAuthCookie(request.headers.get('User-Agent') || 'null', encryptionSecret, adminPassword);
  return timingSafeEqual(authCookie, expected);
}

/**
 * 校验登录表单密码（恒定时间比较）。
 * 原实现先对 adminPassword 去掉 \r\n 再全等比较，这里保留清洗语义。
 */
export function verifyPassword(inputPassword: string | null, adminPassword: string): boolean {
  if (inputPassword === null) return false;
  const expected = typeof adminPassword === 'string' ? adminPassword.replace(/[\r\n]/g, '') : String(adminPassword);
  return timingSafeEqual(inputPassword, expected);
}
